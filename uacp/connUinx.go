package uacp

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/ua"
)

type ConnUnix struct {
	*net.UnixConn
	id  uint32
	ack *Acknowledge

	closeOnce sync.Once
}

func (d *Dialer) DialUnix(ctx context.Context, endpoint string) (*ConnUnix, error) {
	add := strings.Split(endpoint, ":")
	dl := d.Dialer
	if dl == nil {
		dl = &net.Dialer{}
	}
	fmt.Println(add[1])
	c, err := dl.DialContext(ctx, "unix", add[1])
	if err != nil {

		return nil, err
	}

	conn, err := NewConnUnix(c.(*net.UnixConn), d.ClientACK)
	if err != nil {
		c.Close()
		return nil, err
	}

	debug.Printf("uacp %d: start HEL/ACK handshake", conn.id)
	if err := conn.Handshake(endpoint); err != nil {
		debug.Printf("uacp %d: HEL/ACK handshake failed: %s", conn.id, err)
		conn.Close()
		return nil, err
	}
	return conn, nil

}

func NewConnUnix(c *net.UnixConn, ack *Acknowledge) (*ConnUnix, error) {
	if c == nil {
		return nil, fmt.Errorf("no connection")
	}
	if ack == nil {
		ack = DefaultClientACK
	}
	return &ConnUnix{UnixConn: c, id: nextid(), ack: ack}, nil
}

func (c *ConnUnix) ID() uint32 {
	return c.id
}

func (c *ConnUnix) ReceiveBufSize() uint32 {
	return c.ack.ReceiveBufSize
}

func (c *ConnUnix) SendBufSize() uint32 {
	return c.ack.SendBufSize
}

func (c *ConnUnix) MaxMessageSize() uint32 {
	return c.ack.MaxMessageSize
}

func (c *ConnUnix) MaxChunkCount() uint32 {
	return c.ack.MaxChunkCount
}

func (c *ConnUnix) Close() (err error) {
	err = io.EOF
	c.closeOnce.Do(func() { err = c.close() })
	return err
}

func (c *ConnUnix) close() error {
	debug.Printf("uacp %d: close", c.id)
	return c.UnixConn.Close()
}

func (c *ConnUnix) Handshake(endpoint string) error {
	hel := &Hello{
		Version:        c.ack.Version,
		ReceiveBufSize: c.ack.ReceiveBufSize,
		SendBufSize:    c.ack.SendBufSize,
		MaxMessageSize: c.ack.MaxMessageSize,
		MaxChunkCount:  c.ack.MaxChunkCount,
		EndpointURL:    endpoint,
	}

	if err := c.Send("HELF", hel); err != nil {
		return err
	}

	b, err := c.Receive()
	if err != nil {
		return err
	}

	msgtyp := string(b[:4])
	switch msgtyp {
	case "ACKF":
		ack := new(Acknowledge)
		if _, err := ack.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ACK failed: %s", err)
		}
		if ack.Version != 0 {
			return errors.Errorf("uacp: invalid version %d", ack.Version)
		}
		if ack.MaxChunkCount == 0 {
			ack.MaxChunkCount = DefaultMaxChunkCount
			debug.Printf("uacp %d: server has no chunk limit. Using %d", c.id, ack.MaxChunkCount)
		}
		if ack.MaxMessageSize == 0 {
			ack.MaxMessageSize = DefaultMaxMessageSize
			debug.Printf("uacp %d: server has no message size limit. Using %d", c.id, ack.MaxMessageSize)
		}
		c.ack = ack
		debug.Printf("uacp %d: recv %#v", c.id, ack)
		return nil

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ERR failed: %s", err)
		}
		debug.Printf("uacp %d: recv %#v", c.id, errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return errors.Errorf("invalid handshake packet %q", msgtyp)
	}
}

func (c *ConnUnix) srvhandshake(endpoint string) error {
	b, err := c.Receive()
	if err != nil {
		c.SendError(ua.StatusBadTCPInternalError)
		return err
	}

	// HEL or RHE?
	msgtyp := string(b[:4])
	msg := b[hdrlen:]
	switch msgtyp {
	case "HELF":
		hel := new(Hello)
		if _, err := hel.Decode(msg); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		if hel.EndpointURL != endpoint {
			c.SendError(ua.StatusBadTCPEndpointURLInvalid)
			return errors.Errorf("uacp: invalid endpoint url %s", hel.EndpointURL)
		}
		if err := c.Send("ACKF", c.ack); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		debug.Printf("uacp %d: recv %#v", c.id, hel)
		return nil

	case "RHEF":
		rhe := new(ReverseHello)
		if _, err := rhe.Decode(msg); err != nil {
			c.SendError(ua.StatusBadTCPInternalError)
			return err
		}
		if rhe.EndpointURL != endpoint {
			c.SendError(ua.StatusBadTCPEndpointURLInvalid)
			return errors.Errorf("uacp: invalid endpoint url %s", rhe.EndpointURL)
		}
		debug.Printf("uacp %d: connecting to %s", c.id, rhe.ServerURI)
		c.Close()
		var dialer net.Dialer
		c2, err := dialer.DialContext(context.Background(), "tcp", rhe.ServerURI)
		if err != nil {
			return err
		}
		c.UnixConn = c2.(*net.UnixConn)
		debug.Printf("uacp %d: recv %#v", c.id, rhe)
		return nil

	case "ERRF":
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:]); err != nil {
			return errors.Errorf("uacp: decode ERR failed: %s", err)
		}
		debug.Printf("uacp %d: recv %#v", c.id, errf)
		return errf

	default:
		c.SendError(ua.StatusBadTCPInternalError)
		return errors.Errorf("invalid handshake packet %q", msgtyp)
	}
}

// hdrlen is the size of the uacp header
//const hdrlen = 8

// Receive reads a full UACP message from the underlying connection.
// The size of b must be at least ReceiveBufSize. Otherwise,
// the function returns an error.
func (c *ConnUnix) Receive() ([]byte, error) {
	// TODO(kung-foo): allow user-specified buffer
	// TODO(kung-foo): sync.Pool
	b := make([]byte, c.ack.ReceiveBufSize)

	if _, err := io.ReadFull(c, b[:hdrlen]); err != nil {
		// todo(fs): do not wrap this error since it hides io.EOF
		// todo(fs): use golang.org/x/xerrors
		return nil, err
	}

	var h Header
	if _, err := h.Decode(b[:hdrlen]); err != nil {
		return nil, errors.Errorf("uacp: header decode failed: %s", err)
	}

	if h.MessageSize > c.ack.ReceiveBufSize {
		return nil, errors.Errorf("uacp: message too large: %d > %d bytes", h.MessageSize, c.ack.ReceiveBufSize)
	}

	if _, err := io.ReadFull(c, b[hdrlen:h.MessageSize]); err != nil {
		// todo(fs): do not wrap this error since it hides io.EOF
		// todo(fs): use golang.org/x/xerrors
		return nil, err
	}

	debug.Printf("uacp %d: recv %s%c with %d bytes", c.id, h.MessageType, h.ChunkType, h.MessageSize)

	if h.MessageType == "ERR" {
		errf := new(Error)
		if _, err := errf.Decode(b[hdrlen:h.MessageSize]); err != nil {
			return nil, errors.Errorf("uacp: failed to decode ERRF message: %s", err)
		}
		return nil, errf
	}
	return b[:h.MessageSize], nil
}

func (c *ConnUnix) Send(typ string, msg interface{}) error {
	if len(typ) != 4 {
		return errors.Errorf("invalid msg type: %s", typ)
	}

	body, err := ua.Encode(msg)
	if err != nil {
		return errors.Errorf("encode msg failed: %s", err)
	}

	h := Header{
		MessageType: typ[:3],
		ChunkType:   typ[3],
		MessageSize: uint32(len(body) + hdrlen),
	}

	if h.MessageSize > c.ack.SendBufSize {
		return errors.Errorf("send packet too large: %d > %d bytes", h.MessageSize, c.ack.SendBufSize)
	}

	hdr, err := h.Encode()
	if err != nil {
		return errors.Errorf("encode hdr failed: %s", err)
	}

	b := append(hdr, body...)
	if _, err := c.Write(b); err != nil {
		return errors.Errorf("write failed: %s", err)
	}
	debug.Printf("uacp %d: sent %s with %d bytes", c.id, typ, len(b))

	return nil
}

func (c *ConnUnix) SendError(code ua.StatusCode) {
	// we swallow the error to silence complaints from the linter
	// since sending an error will close the connection and we
	// want to bubble a different error up.
	_ = c.Send("ERRF", &Error{ErrorCode: uint32(code)})
}
