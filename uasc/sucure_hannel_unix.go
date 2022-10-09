package uasc

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
)

type SecureChannelUnix struct {
	endpointURL string

	// c is the uacp connection
	c *uacp.ConnUnix

	// cfg is the configuration for the secure channel.
	cfg *Config

	// time returns the current time. When not set it defaults to time.Now().
	time func() time.Time

	// closing is channel used to indicate to go routines that the secure channel is closing
	closing      chan struct{}
	disconnected chan struct{}

	// startDispatcher ensures only one dispatcher is running
	startDispatcher sync.Once

	// requestID is a "global" counter shared between multiple channels and tokens
	requestID   uint32
	requestIDMu sync.Mutex

	// instances maps secure channel IDs to a list to channel states
	instances      map[uint32][]*channelInstanceUnix
	activeInstance *channelInstanceUnix
	instancesMu    sync.Mutex

	// prevent sending msg when secure channel renewal occurs
	reqLocker  *conditionLocker
	rcvLocker  *conditionLocker
	pendingReq sync.WaitGroup

	// handles maps request IDs to response channels
	handlers   map[uint32]chan *response
	handlersMu sync.Mutex

	// chunks maintains a temporary list of chunks for a given request ID
	chunks   map[uint32][]*MessageChunk
	chunksMu sync.Mutex

	// openingInstance is a temporary var that allows the dispatcher know how to handle a open channel request
	// note: we only allow a single "open" request in flight at any point in time. The mutex is held for the entire
	// duration of the "open" request.
	openingInstance *channelInstanceUnix
	openingMu       sync.Mutex

	// errorCh receive dispatcher errors
	errCh chan<- error

	closeOnce sync.Once
}

func NewSecureChannelUnix(endpoint string, c *uacp.ConnUnix, cfg *Config, errCh chan<- error) (*SecureChannelUnix, error) {
	if c == nil {
		return nil, errors.Errorf("no connection")
	}

	if cfg == nil {
		return nil, errors.Errorf("no secure channel config")
	}

	if cfg.SecurityPolicyURI != ua.SecurityPolicyURINone {
		if cfg.SecurityMode == ua.MessageSecurityModeNone {
			return nil, errors.Errorf("invalid channel config: Security policy '%s' cannot be used with '%s'", cfg.SecurityPolicyURI, cfg.SecurityMode)
		}
		if cfg.LocalKey == nil {
			return nil, errors.Errorf("invalid channel config: Security policy '%s' requires a private key", cfg.SecurityPolicyURI)
		}
	}

	// Force the security mode to None if the policy is also None
	// TODO: I don't like that a SecureChannel changes the incoming config
	if cfg.SecurityPolicyURI == ua.SecurityPolicyURINone {
		cfg.SecurityMode = ua.MessageSecurityModeNone
	}

	s := &SecureChannelUnix{
		endpointURL:  endpoint,
		c:            c,
		cfg:          cfg,
		requestID:    cfg.RequestIDSeed,
		reqLocker:    newConditionLocker(),
		rcvLocker:    newConditionLocker(),
		errCh:        errCh,
		closing:      make(chan struct{}),
		disconnected: make(chan struct{}),
		instances:    make(map[uint32][]*channelInstanceUnix),
		chunks:       make(map[uint32][]*MessageChunk),
		handlers:     make(map[uint32]chan *response),
	}

	return s, nil
}

func (s *SecureChannelUnix) getActiveChannelInstance() (*channelInstanceUnix, error) {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	if s.activeInstance == nil {
		return nil, errors.Errorf("sechan: secure channel not open.")
	}
	return s.activeInstance, nil
}

func (s *SecureChannelUnix) dispatcher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer func() {
		close(s.disconnected)
	}()

	for {
		select {
		case <-s.closing:
			return
		default:
			resp := s.receive(ctx)

			if resp.Err != nil {
				select {
				case <-s.closing:
					return
				default:
					select {
					case s.errCh <- resp.Err:
					default:
					}
				}
			}

			if resp.Err == io.EOF {
				return
			}

			if resp.Err != nil {
				debug.Printf("uasc %d/%d: err: %v", s.c.ID(), resp.ReqID, resp.Err)
			} else {
				debug.Printf("uasc %d/%d: recv %T", s.c.ID(), resp.ReqID, resp.V)
			}

			ch, ok := s.popHandler(resp.ReqID)

			if !ok {
				debug.Printf("uasc %d/%d: no handler for %T", s.c.ID(), resp.ReqID, resp.V)
				continue
			}

			// HACK
			if _, ok := resp.V.(*ua.OpenSecureChannelResponse); ok {
				s.rcvLocker.lock()
			}

			debug.Printf("uasc %d/%d: sending %T to handler", s.c.ID(), resp.ReqID, resp.V)
			select {
			case ch <- resp:
			default:
				// this should never happen since the chan is of size one
				debug.Printf("uasc %d/%d: unexpected state. channel write should always succeed.", s.c.ID(), resp.ReqID)
			}

			s.rcvLocker.waitIfLock()
		}
	}
}

// receive receives message chunks from the secure channel, decodes and forwards
// them to the registered callback channel, if there is one. Otherwise,
// the message is dropped.
func (s *SecureChannelUnix) receive(ctx context.Context) *response {
	for {
		select {
		case <-ctx.Done():
			return &response{Err: ctx.Err()}

		default:
			chunk, err := s.readChunk()
			if err == io.EOF {
				debug.Printf("uasc %d: readChunk EOF", s.c.ID())
				return &response{Err: err}
			}

			if err != nil {
				return &response{Err: err}
			}

			hdr := chunk.Header
			reqID := chunk.SequenceHeader.RequestID

			resp := &response{
				ReqID: reqID,
				SCID:  chunk.MessageHeader.Header.SecureChannelID,
			}

			debug.Printf("uasc %d/%d: recv %s%c with %d bytes", s.c.ID(), reqID, hdr.MessageType, hdr.ChunkType, hdr.MessageSize)

			s.chunksMu.Lock()

			switch hdr.ChunkType {
			case 'A':
				delete(s.chunks, reqID)
				s.chunksMu.Unlock()

				msga := new(MessageAbort)
				if _, err := msga.Decode(chunk.Data); err != nil {
					debug.Printf("uasc %d/%d: invalid MSGA chunk. %s", s.c.ID(), reqID, err)
					resp.Err = ua.StatusBadDecodingError
					return resp
				}

				return &response{ReqID: reqID, Err: ua.StatusCode(msga.ErrorCode)}

			case 'C':
				s.chunks[reqID] = append(s.chunks[reqID], chunk)
				if n := len(s.chunks[reqID]); uint32(n) > s.c.MaxChunkCount() {
					delete(s.chunks, reqID)
					s.chunksMu.Unlock()
					resp.Err = errors.Errorf("too many chunks: %d > %d", n, s.c.MaxChunkCount())
					return resp
				}
				s.chunksMu.Unlock()
				continue
			}

			// merge chunks
			all := append(s.chunks[reqID], chunk)
			delete(s.chunks, reqID)

			s.chunksMu.Unlock()

			b, err := mergeChunks(all)
			if err != nil {
				resp.Err = err
				return resp
			}

			if uint32(len(b)) > s.c.MaxMessageSize() {
				resp.Err = errors.Errorf("message too large: %d > %d", uint32(len(b)), s.c.MaxMessageSize())
				return resp
			}

			// since we are not decoding the ResponseHeader separately
			// we need to drop every message that has an error since we
			// cannot get to the RequestHandle in the ResponseHeader.
			// To fix this we must a) decode the ResponseHeader separately
			// and subsequently remove it and the TypeID from all service
			// structs and tests. We also need to add a deadline to all
			// handlers and check them periodically to time them out.
			_, svc, err := ua.DecodeService(b)
			if err != nil {
				resp.Err = err
				return resp
			}

			resp.V = svc

			// If the service status is not OK then bubble
			// that error up to the caller.
			if r, ok := svc.(ua.Response); ok {
				if status := r.Header().ServiceResult; status != ua.StatusOK {
					resp.Err = status
					return resp
				}
			}

			return resp
		}
	}
}

func (s *SecureChannelUnix) readChunk() (*MessageChunk, error) {
	// read a full message from the underlying conn.
	b, err := s.c.Receive()
	if err == io.EOF || len(b) == 0 {
		return nil, io.EOF
	}
	// do not wrap this error since it hides conn error
	var uacperr *uacp.Error
	if errors.As(err, &uacperr) {
		return nil, err
	}
	if err != nil {
		return nil, errors.Errorf("sechan: read header failed: %s %#v", err, err)
	}

	const hdrlen = 12 // TODO: move to pkg level const
	h := new(Header)
	if _, err := h.Decode(b[:hdrlen]); err != nil {
		return nil, errors.Errorf("sechan: decode header failed: %s", err)
	}

	// decode the other headers
	m := new(MessageChunk)
	if _, err := m.Decode(b); err != nil {
		return nil, errors.Errorf("sechan: decode chunk failed: %s", err)
	}

	var decryptWith *channelInstanceUnix

	switch m.MessageType {
	case "OPN":
		// Make sure we have a valid security header
		if m.AsymmetricSecurityHeader == nil {
			return nil, ua.StatusBadDecodingError // todo(dh): check if this is the correct error
		}

		if s.openingInstance == nil {
			return nil, errors.Errorf("sechan: invalid state. openingInstance is nil.")
		}

		if m.SecurityPolicyURI != ua.SecurityPolicyURINone {
			s.cfg.RemoteCertificate = m.AsymmetricSecurityHeader.SenderCertificate
			debug.Printf("uasc %d: setting securityPolicy to %s", s.c.ID(), m.SecurityPolicyURI)
		}

		s.cfg.SecurityPolicyURI = m.SecurityPolicyURI

		decryptWith = s.openingInstance
	case "CLO":
		return nil, io.EOF
	case "MSG":
		// noop
	default:
		return nil, errors.Errorf("sechan: unknown message type: %s", m.MessageType)
	}

	// Decrypt the block and put data back into m.Data
	m.Data, err = s.verifyAndDecrypt(m, b, decryptWith)
	if err != nil {
		return nil, err
	}

	n, err := m.SequenceHeader.Decode(m.Data)
	if err != nil {
		return nil, errors.Errorf("sechan: decode sequence header failed: %s", err)
	}
	m.Data = m.Data[n:]

	return m, nil
}

// verifyAndDecrypt verifies and optionally decrypts a message. if `instance` is given, then it will only use that
// state. Otherwise it will look up states by channel ID and try each.
func (s *SecureChannelUnix) verifyAndDecrypt(m *MessageChunk, b []byte, instance *channelInstanceUnix) ([]byte, error) {
	if instance != nil {
		return instance.verifyAndDecrypt(m, b)
	}

	instances := s.getInstancesBySecureChannelID(m.MessageHeader.SecureChannelID)
	if len(instances) == 0 {
		return nil, errors.Errorf("sechan: unable to find instance for SecureChannelID=%d", m.MessageHeader.SecureChannelID)
	}

	var (
		err      error
		verified []byte
	)

	for i := len(instances) - 1; i >= 0; i-- {
		if verified, err = instances[i].verifyAndDecrypt(m, b); err == nil {
			return verified, nil
		}
		debug.Printf("uasc %d: attempting an older channel state...", s.c.ID())
	}

	return nil, err
}

func (s *SecureChannelUnix) getInstancesBySecureChannelID(id uint32) []*channelInstanceUnix {
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()

	instances := s.instances[id]
	if instances == nil {
		return nil
	}

	// return a copy of the slice in case a renewal is triggered
	cpy := make([]*channelInstanceUnix, len(instances))
	copy(cpy, instances)

	return instances
}

func (s *SecureChannelUnix) LocalEndpoint() string {
	return s.endpointURL
}

func (s *SecureChannelUnix) Open(ctx context.Context) error {
	return s.open(ctx, nil, ua.SecurityTokenRequestTypeIssue)
}

func (s *SecureChannelUnix) open(ctx context.Context, instance *channelInstanceUnix, requestType ua.SecurityTokenRequestType) error {
	defer s.rcvLocker.unlock()

	s.openingMu.Lock()
	defer s.openingMu.Unlock()

	if s.openingInstance != nil {
		return errors.Errorf("sechan: invalid state. openingInstance must be nil when opening a new secure channel.")
	}

	var (
		err       error
		localKey  *rsa.PrivateKey
		remoteKey *rsa.PublicKey
	)

	s.startDispatcher.Do(func() {
		go s.dispatcher()
	})

	// Set the encryption methods to Asymmetric with the appropriate
	// public keys.  OpenSecureChannel is always encrypted with the
	// asymmetric algorithms.
	// The default value of the encryption algorithm method is the
	// SecurityModeNone so no additional work is required for that case
	if s.cfg.SecurityMode != ua.MessageSecurityModeNone {
		localKey = s.cfg.LocalKey
		// todo(dh): move this into the uapolicy package proper or
		// adjust the Asymmetric method to receive a certificate instead
		remoteCert, err := x509.ParseCertificate(s.cfg.RemoteCertificate)
		if err != nil {
			return err
		}
		var ok bool
		if remoteKey, ok = remoteCert.PublicKey.(*rsa.PublicKey); !ok {
			return ua.StatusBadCertificateInvalid
		}
	}

	algo, err := uapolicy.Asymmetric(s.cfg.SecurityPolicyURI, localKey, remoteKey)
	if err != nil {
		return err
	}

	s.openingInstance = newChannelInstanceUnix(s)

	if requestType == ua.SecurityTokenRequestTypeRenew {
		// TODO: lock? sequenceNumber++?
		// this seems racy. if another request goes out while the other open request is in flight then won't an error
		// be raised on the server? can the sequenceNumber be as "global" as the request ID?
		s.openingInstance.sequenceNumber = instance.sequenceNumber
		s.openingInstance.secureChannelID = instance.secureChannelID
	}

	// trigger cleanup after we are all done
	defer func() {
		if s.openingInstance == nil || s.openingInstance.state != channelActive {
			debug.Printf("uasc %d: failed to open a new secure channel", s.c.ID())
		}
		s.openingInstance = nil
	}()

	reqID := s.nextRequestID()

	s.openingInstance.algo = algo
	s.openingInstance.SetMaximumBodySize(int(s.c.SendBufSize()))

	localNonce, err := algo.MakeNonce()
	if err != nil {
		return err
	}

	req := &ua.OpenSecureChannelRequest{
		ClientProtocolVersion: 0,
		RequestType:           requestType,
		SecurityMode:          s.cfg.SecurityMode,
		ClientNonce:           localNonce,
		RequestedLifetime:     s.cfg.Lifetime,
	}

	return s.sendRequestWithTimeout(ctx, req, reqID, s.openingInstance, nil, s.cfg.RequestTimeout, func(v interface{}) error {
		resp, ok := v.(*ua.OpenSecureChannelResponse)
		if !ok {
			return errors.Errorf("got %T, want OpenSecureChannelResponse", v)
		}
		return s.handleOpenSecureChannelResponse(resp, localNonce, s.openingInstance)
	})
}

func (s *SecureChannelUnix) handleOpenSecureChannelResponse(resp *ua.OpenSecureChannelResponse, localNonce []byte, instance *channelInstanceUnix) (err error) {
	instance.state = channelActive
	instance.secureChannelID = resp.SecurityToken.ChannelID
	instance.securityTokenID = resp.SecurityToken.TokenID
	instance.createdAt = resp.SecurityToken.CreatedAt
	instance.revisedLifetime = time.Millisecond * time.Duration(resp.SecurityToken.RevisedLifetime)

	// allow the client to specify a lifetime that is smaller
	if int64(s.cfg.Lifetime) < int64(instance.revisedLifetime/time.Millisecond) {
		instance.revisedLifetime = time.Millisecond * time.Duration(s.cfg.Lifetime)
	}

	if instance.algo, err = uapolicy.Symmetric(s.cfg.SecurityPolicyURI, localNonce, resp.ServerNonce); err != nil {
		return err
	}

	instance.SetMaximumBodySize(int(s.c.SendBufSize()))

	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()

	s.instances[resp.SecurityToken.ChannelID] = append(
		s.instances[resp.SecurityToken.ChannelID],
		s.openingInstance,
	)

	s.activeInstance = instance

	debug.Printf("uasc %d: received security token. channelID=%d tokenID=%d createdAt=%s lifetime=%s", s.c.ID(), instance.secureChannelID, instance.securityTokenID, instance.createdAt.Format(time.RFC3339), instance.revisedLifetime)

	go s.scheduleRenewal(instance)
	go s.scheduleExpiration(instance)

	return
}

func (s *SecureChannelUnix) scheduleRenewal(instance *channelInstanceUnix) {
	// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.5.2/#5.5.2.1
	// Clients should request a new SecurityToken after 75 % of its lifetime has elapsed. This should ensure that
	// clients will receive the new SecurityToken before the old one actually expire
	const renewAfter = 0.75
	when := time.Second * time.Duration(instance.revisedLifetime.Seconds()*renewAfter)

	debug.Printf("uasc %d: security token is refreshed at %s (%s). channelID=%d tokenID=%d", s.c.ID(), time.Now().UTC().Add(when).Format(time.RFC3339), when, instance.secureChannelID, instance.securityTokenID)

	t := time.NewTimer(when)
	defer t.Stop()

	select {
	case <-s.closing:
		return
	case <-t.C:
	}

	// TODO: where should this error go?
	_ = s.renew(instance)
}

func (s *SecureChannelUnix) renew(instance *channelInstanceUnix) error {
	// lock ensure no one else renews this at the same time
	s.reqLocker.lock()
	defer s.reqLocker.unlock()
	s.pendingReq.Wait()
	instance.Lock()
	defer instance.Unlock()

	return s.open(context.Background(), instance, ua.SecurityTokenRequestTypeRenew)
}

func (s *SecureChannelUnix) scheduleExpiration(instance *channelInstanceUnix) {
	// https://reference.opcfoundation.org/v104/Core/docs/Part4/5.5.2/#5.5.2.1
	// Clients should accept Messages secured by an expired SecurityToken for up to 25 % of the token lifetime.
	const expireAfter = 1.25
	when := instance.createdAt.Add(time.Second * time.Duration(instance.revisedLifetime.Seconds()*expireAfter))

	debug.Printf("uasc %d: security token expires at %s. channelID=%d tokenID=%d", s.c.ID(), when.UTC().Format(time.RFC3339), instance.secureChannelID, instance.securityTokenID)

	t := time.NewTimer(time.Until(when))

	select {
	case <-s.closing:
		return
	case <-t.C:
	}

	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()

	oldInstances := s.instances[instance.securityTokenID]

	s.instances[instance.securityTokenID] = []*channelInstanceUnix{}

	for _, oldInstance := range oldInstances {
		if oldInstance.secureChannelID != instance.secureChannelID {
			// something has gone horribly wrong!
			debug.Printf("uasc %d: secureChannelID mismatch during scheduleExpiration!", s.c.ID())
		}
		if oldInstance.securityTokenID == instance.securityTokenID {
			continue
		}
		s.instances[instance.securityTokenID] = append(
			s.instances[instance.securityTokenID],
			oldInstance,
		)
	}
}

func (s *SecureChannelUnix) sendRequestWithTimeout(
	ctx context.Context,
	req ua.Request,
	reqID uint32,
	instance *channelInstanceUnix,
	authToken *ua.NodeID,
	timeout time.Duration,
	h func(interface{}) error) error {

	s.pendingReq.Add(1)
	respRequired := h != nil

	ch, err := s.sendAsyncWithTimeout(ctx, req, reqID, instance, authToken, respRequired, timeout)
	s.pendingReq.Done()
	if err != nil {
		return err
	}

	if !respRequired {
		return nil
	}

	// `+ timeoutLeniency` to give the server a chance to respond to TimeoutHint
	timer := time.NewTimer(timeout + timeoutLeniency)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		s.popHandler(reqID)
		return ctx.Err()
	case <-s.disconnected:
		s.popHandler(reqID)
		return io.EOF
	case resp := <-ch:
		if resp.Err != nil {
			if resp.V != nil {
				_ = h(resp.V) // ignore result because resp.Err takes precedence
			}
			return resp.Err
		}
		return h(resp.V)
	case <-timer.C:
		s.popHandler(reqID)
		return ua.StatusBadTimeout
	}
}

func (s *SecureChannelUnix) popHandler(reqID uint32) (chan *response, bool) {
	s.handlersMu.Lock()
	defer s.handlersMu.Unlock()

	ch, ok := s.handlers[reqID]
	if ok {
		delete(s.handlers, reqID)
	}
	return ch, ok
}

func (s *SecureChannelUnix) Renew(ctx context.Context) error {
	instance, err := s.getActiveChannelInstance()
	if err != nil {
		return err
	}

	return s.renew(instance)
}

// SendRequest sends the service request and calls h with the response.
// Deprecated: Starting with v0.5 this method will require a context
// and the corresponding XXXWithContext(ctx) method will be removed.
func (s *SecureChannelUnix) SendRequest(req ua.Request, authToken *ua.NodeID, h func(interface{}) error) error {
	return s.SendRequestWithContext(context.Background(), req, authToken, h)
}

// Note: This method will be replaced by the non "WithContext()" version
// of this method.
func (s *SecureChannelUnix) SendRequestWithContext(ctx context.Context, req ua.Request, authToken *ua.NodeID, h func(interface{}) error) error {
	return s.SendRequestWithTimeoutWithContext(ctx, req, authToken, s.cfg.RequestTimeout, h)
}

// Deprecated: Starting with v0.5 this method will require a context
// and the corresponding XXXWithContext(ctx) method will be removed.
func (s *SecureChannelUnix) SendRequestWithTimeout(req ua.Request, authToken *ua.NodeID, timeout time.Duration, h func(interface{}) error) error {
	return s.SendRequestWithTimeoutWithContext(context.Background(), req, authToken, timeout, h)
}

// Note: This method will be replaced by the non "WithContext()" version
// of this method.
func (s *SecureChannelUnix) SendRequestWithTimeoutWithContext(ctx context.Context, req ua.Request, authToken *ua.NodeID, timeout time.Duration, h func(interface{}) error) error {
	s.reqLocker.waitIfLock()
	active, err := s.getActiveChannelInstance()
	if err != nil {
		return err
	}

	return s.sendRequestWithTimeout(ctx, req, s.nextRequestID(), active, authToken, timeout, h)
}

func (s *SecureChannelUnix) sendAsyncWithTimeout(
	ctx context.Context,
	req ua.Request,
	reqID uint32,
	instance *channelInstanceUnix,
	authToken *ua.NodeID,
	respRequired bool,
	timeout time.Duration,
) (<-chan *response, error) {

	instance.Lock()
	defer instance.Unlock()

	m, err := instance.newRequestMessage(req, reqID, authToken, timeout)
	if err != nil {
		return nil, err
	}

	var resp chan *response

	if respRequired {
		// register the handler if a callback was passed
		resp = make(chan *response, 1)

		s.handlersMu.Lock()

		if s.handlers[reqID] != nil {
			s.handlersMu.Unlock()
			return nil, errors.Errorf("error: duplicate handler registration for request id %d", reqID)
		}

		s.handlers[reqID] = resp
		s.handlersMu.Unlock()
	}

	chunks, err := m.EncodeChunks(instance.maxBodySize)
	if err != nil {
		return nil, err
	}

	for i, chunk := range chunks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if i > 0 { // fix sequence number on subsequent chunks
			number := instance.nextSequenceNumber()
			binary.LittleEndian.PutUint32(chunk[16:], uint32(number))
		}

		chunk, err = instance.signAndEncrypt(m, chunk)
		if err != nil {
			return nil, err
		}

		// send the message
		var n int
		if n, err = s.c.Write(chunk); err != nil {
			return nil, err
		}

		atomic.AddUint64(&instance.bytesSent, uint64(n))
		atomic.AddUint32(&instance.messagesSent, 1)

		debug.Printf("uasc %d/%d: send %T with %d bytes", s.c.ID(), reqID, req, len(chunk))
	}

	return resp, nil
}

func (s *SecureChannelUnix) nextRequestID() uint32 {
	s.requestIDMu.Lock()
	defer s.requestIDMu.Unlock()

	s.requestID++
	if s.requestID == 0 {
		s.requestID = 1
	}

	return s.requestID
}

// Close closes an existing secure channel
func (s *SecureChannelUnix) Close() (err error) {
	// https://gitlab.zmjkf.cn/zmos/opcua/pull/470
	// guard against double close until we found the root cause
	err = io.EOF
	s.closeOnce.Do(func() { err = s.close() })
	return
}

func (s *SecureChannelUnix) close() error {
	debug.Printf("uasc %d: Close()", s.c.ID())

	defer func() {
		close(s.closing)
	}()

	s.reqLocker.unlock()
	s.rcvLocker.unlock()

	select {
	case <-s.disconnected:
		return io.EOF
	default:
	}

	err := s.SendRequestWithContext(context.Background(), &ua.CloseSecureChannelRequest{}, nil, nil)
	if err != nil {
		return err
	}

	return io.EOF
}

func (s *SecureChannelUnix) timeNow() time.Time {
	if s.time != nil {
		return s.time()
	}
	return time.Now()
}

func (s *SecureChannelUnix) NewSessionSignature(cert, nonce []byte) ([]byte, string, error) {
	if s.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return nil, "", nil
	}

	remoteX509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, "", err
	}
	remoteKey := remoteX509Cert.PublicKey.(*rsa.PublicKey)

	enc, err := uapolicy.Asymmetric(s.cfg.SecurityPolicyURI, s.cfg.LocalKey, remoteKey)
	if err != nil {
		return nil, "", err
	}

	sig, err := enc.Signature(append(cert, nonce...))
	if err != nil {
		return nil, "", err
	}
	sigAlg := enc.SignatureURI()

	return sig, sigAlg, nil
}

// VerifySessionSignature checks the integrity of a Create/Activate Session response's signature
func (s *SecureChannelUnix) VerifySessionSignature(cert, nonce, signature []byte) error {
	if s.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return nil
	}

	remoteX509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return err
	}
	remoteKey := remoteX509Cert.PublicKey.(*rsa.PublicKey)

	enc, err := uapolicy.Asymmetric(s.cfg.SecurityPolicyURI, s.cfg.LocalKey, remoteKey)
	if err != nil {
		return err
	}
	err = enc.VerifySignature(append(s.cfg.Certificate, nonce...), signature)
	if err != nil {
		return err
	}

	return nil
}

// EncryptUserPassword issues a new signature for the client to send in ActivateSessionRequest
func (s *SecureChannelUnix) EncryptUserPassword(policyURI, password string, cert, nonce []byte) ([]byte, string, error) {
	// If the User ID Token's policy was null, then default to the secure channel's policy
	if policyURI == "" {
		policyURI = s.cfg.SecurityPolicyURI
	}

	if policyURI == ua.SecurityPolicyURINone {
		return []byte(password), "", nil
	}

	remoteX509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, "", err
	}
	remoteKey := remoteX509Cert.PublicKey.(*rsa.PublicKey)

	enc, err := uapolicy.Asymmetric(policyURI, s.cfg.LocalKey, remoteKey)
	if err != nil {
		return nil, "", err
	}

	l := len(password) + len(nonce)
	secret := make([]byte, 4)
	binary.LittleEndian.PutUint32(secret, uint32(l))
	secret = append(secret, []byte(password)...)
	secret = append(secret, nonce...)
	pass, err := enc.Encrypt(secret)
	if err != nil {
		return nil, "", err
	}
	passAlg := enc.EncryptionURI()

	return pass, passAlg, nil
}

// NewUserTokenSignature issues a new signature for the client to send in ActivateSessionRequest
func (s *SecureChannelUnix) NewUserTokenSignature(policyURI string, cert, nonce []byte) ([]byte, string, error) {
	if policyURI == ua.SecurityPolicyURINone {
		return nil, "", nil
	}

	remoteX509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, "", err
	}
	remoteKey := remoteX509Cert.PublicKey.(*rsa.PublicKey)

	enc, err := uapolicy.Asymmetric(policyURI, s.cfg.LocalKey, remoteKey)
	if err != nil {
		return nil, "", err
	}

	sig, err := enc.Signature(append(cert, nonce...))
	if err != nil {
		return nil, "", err
	}
	sigAlg := enc.SignatureURI()

	return sig, sigAlg, nil
}

//func mergeChunks(chunks []*MessageChunk) ([]byte, error) {
//	if len(chunks) == 0 {
//		return nil, nil
//	}
//	if len(chunks) == 1 {
//		return chunks[0].Data, nil
//	}
//
//	var b []byte
//	var seqnr uint32
//	for _, c := range chunks {
//		if c.SequenceHeader.SequenceNumber == seqnr {
//			continue // duplicate chunk
//		}
//		seqnr = c.SequenceHeader.SequenceNumber
//		b = append(b, c.Data...)
//	}
//	return b, nil
//}

type channelInstanceUnix struct {
	sync.Mutex
	sc              *SecureChannelUnix
	state           instanceState
	createdAt       time.Time
	revisedLifetime time.Duration
	secureChannelID uint32
	securityTokenID uint32
	sequenceNumber  uint32
	algo            *uapolicy.EncryptionAlgorithm
	maxBodySize     uint32

	bytesSent uint64 // atomic.Load/Store - needs to be aligned for 32bit systems
	// bytesReceived    uint64
	messagesSent uint32 // atomic.Load/Store
	// messagesReceived uint32
}

func newChannelInstanceUnix(sc *SecureChannelUnix) *channelInstanceUnix {
	return &channelInstanceUnix{
		sc:    sc,
		state: channelOpening,
	}
}

func (c *channelInstanceUnix) nextSequenceNumber() uint32 {
	// lock must be held
	c.sequenceNumber++
	if c.sequenceNumber > math.MaxUint32-1023 {
		c.sequenceNumber = 1
	}

	return c.sequenceNumber
}

func (c *channelInstanceUnix) newRequestMessage(req ua.Request, reqID uint32, authToken *ua.NodeID, timeout time.Duration) (*Message, error) {
	typeID := ua.ServiceTypeID(req)
	if typeID == 0 {
		return nil, errors.Errorf("unknown service %T. Did you call register?", req)
	}
	if authToken == nil {
		authToken = ua.NewTwoByteNodeID(0)
	}

	reqHdr := &ua.RequestHeader{
		AuthenticationToken: authToken,
		Timestamp:           c.sc.timeNow(),
		RequestHandle:       reqID, // TODO: can I cheat like this?
	}

	if timeout > 0 && timeout < c.sc.cfg.RequestTimeout {
		timeout = c.sc.cfg.RequestTimeout
	}
	reqHdr.TimeoutHint = uint32(timeout / time.Millisecond)
	req.SetHeader(reqHdr)

	// encode the message
	return c.newMessage(req, typeID, reqID), nil
}

func (c *channelInstanceUnix) newMessage(srv interface{}, typeID uint16, requestID uint32) *Message {
	sequenceNumber := c.nextSequenceNumber()

	switch typeID {
	case id.OpenSecureChannelRequest_Encoding_DefaultBinary, id.OpenSecureChannelResponse_Encoding_DefaultBinary:
		// Do not send the thumbprint for security mode None
		// even if we have a certificate.
		//
		// See https://gitlab.zmjkf.cn/zmos/opcua/issues/259
		thumbprint := c.sc.cfg.Thumbprint
		if c.sc.cfg.SecurityMode == ua.MessageSecurityModeNone {
			thumbprint = nil
		}

		return &Message{
			MessageHeader: &MessageHeader{
				Header:                   NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, c.secureChannelID),
				AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(c.sc.cfg.SecurityPolicyURI, c.sc.cfg.Certificate, thumbprint),
				SequenceHeader:           NewSequenceHeader(sequenceNumber, requestID),
			},
			TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
			Service: srv,
		}

	case id.CloseSecureChannelRequest_Encoding_DefaultBinary, id.CloseSecureChannelResponse_Encoding_DefaultBinary:
		return &Message{
			MessageHeader: &MessageHeader{
				Header:                  NewHeader(MessageTypeCloseSecureChannel, ChunkTypeFinal, c.secureChannelID),
				SymmetricSecurityHeader: NewSymmetricSecurityHeader(c.securityTokenID),
				SequenceHeader:          NewSequenceHeader(sequenceNumber, requestID),
			},
			TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
			Service: srv,
		}

	default:
		return &Message{
			MessageHeader: &MessageHeader{
				Header:                  NewHeader(MessageTypeMessage, ChunkTypeFinal, c.secureChannelID),
				SymmetricSecurityHeader: NewSymmetricSecurityHeader(c.securityTokenID),
				SequenceHeader:          NewSequenceHeader(sequenceNumber, requestID),
			},
			TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
			Service: srv,
		}
	}
}

func (c *channelInstanceUnix) SetMaximumBodySize(chunkSize int) {
	sequenceHeaderSize := 8
	headerSize := 12
	symmetricAlgorithmHeader := 4

	// this is the formula proposed by OPCUA - source node-opcua
	maxBodySize :=
		c.algo.PlaintextBlockSize()*
			((chunkSize-headerSize-symmetricAlgorithmHeader-c.algo.SignatureLength()-1)/c.algo.BlockSize()) -
			sequenceHeaderSize
	c.maxBodySize = uint32(maxBodySize)

	// this is the formula proposed by ERN - source node-opcua
	// maxBlock := (chunkSize - headerSize) / c.algo.BlockSize()
	// c.maxBodySize = c.algo.PlaintextBlockSize()*maxBlock - sequenceHeaderSize - c.algo.SignatureLength() - 1
}

// signAndEncrypt encrypts the message bytes stored in b and returns the
// data signed and encrypted per the security policy information from the
// secure channel.
func (c *channelInstanceUnix) signAndEncrypt(m *Message, b []byte) ([]byte, error) {
	// Nothing to do
	if c.sc.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return b, nil
	}

	isAsymmetric := m.MessageHeader.AsymmetricSecurityHeader != nil

	var headerLength int

	if isAsymmetric {
		headerLength = 12 + m.AsymmetricSecurityHeader.Len()
	} else {
		headerLength = 12 + m.SymmetricSecurityHeader.Len()
	}

	var encryptedLength int
	if c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt || isAsymmetric {
		plaintextBlockSize := c.algo.PlaintextBlockSize()
		paddingLength := plaintextBlockSize - ((len(b[headerLength:]) + c.algo.SignatureLength() + 1) % plaintextBlockSize)

		for i := 0; i <= paddingLength; i++ {
			b = append(b, byte(paddingLength))
		}
		encryptedLength = ((len(b[headerLength:]) + c.algo.SignatureLength()) / plaintextBlockSize) * c.algo.BlockSize()
	} else { // MessageSecurityModeSign
		encryptedLength = len(b[headerLength:]) + c.algo.SignatureLength()
	}

	// Fix header size to account for signing / encryption
	binary.LittleEndian.PutUint32(b[4:], uint32(headerLength+encryptedLength))
	m.Header.MessageSize = uint32(headerLength + encryptedLength)

	signature, err := c.algo.Signature(b)
	if err != nil {
		return nil, ua.StatusBadSecurityChecksFailed
	}

	b = append(b, signature...)
	p := b[headerLength:]
	if c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt || isAsymmetric {
		p, err = c.algo.Encrypt(p)
		if err != nil {
			return nil, ua.StatusBadSecurityChecksFailed
		}
	}
	return append(b[:headerLength], p...), nil
}

func (c *channelInstanceUnix) verifyAndDecrypt(m *MessageChunk, r []byte) ([]byte, error) {
	if c.sc.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return m.Data, nil
	}

	isAsymmetric := m.AsymmetricSecurityHeader != nil

	headerLength := 12

	if isAsymmetric {
		headerLength += m.AsymmetricSecurityHeader.Len()
	} else {
		headerLength += m.SymmetricSecurityHeader.Len()
	}

	b := make([]byte, len(r))
	copy(b, r)

	if c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt || isAsymmetric {
		p, err := c.algo.Decrypt(b[headerLength:])
		if err != nil {
			return nil, ua.StatusBadSecurityChecksFailed
		}
		b = append(b[:headerLength], p...)
	}

	signature := b[len(b)-c.algo.RemoteSignatureLength():]
	messageToVerify := b[:len(b)-c.algo.RemoteSignatureLength()]

	if err := c.algo.VerifySignature(messageToVerify, signature); err != nil {
		return nil, ua.StatusBadSecurityChecksFailed
	}

	var paddingLength int
	if c.sc.cfg.SecurityMode == ua.MessageSecurityModeSignAndEncrypt || isAsymmetric {
		paddingLength = int(messageToVerify[len(messageToVerify)-1]) + 1
	}

	b = messageToVerify[headerLength : len(messageToVerify)-paddingLength]

	return b, nil
}
