package opcua

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/stats"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

func GetEndpointsUnix(ctx context.Context, endpoint string, opts ...Option) ([]*ua.EndpointDescription, error) {
	// AutoReconnect 用于链接断开重连
	opts = append(opts, AutoReconnect(false))
	c := NewClient(endpoint, opts...)

	if err := c.DialUnix(ctx); err != nil {
		return nil, err
	}

	defer c.CloseUnixWithContext(ctx)
	res, err := c.GetEndpointsUnixWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return res.Endpoints, nil

}

func (c *Client) GetEndpointsUnixWithContext(ctx context.Context) (*ua.GetEndpointsResponse, error) {
	stats.Client().Add("GetEndpointsUnix", 1)
	req := &ua.GetEndpointsRequest{
		EndpointURL: c.endpointURL,
	}
	var res *ua.GetEndpointsResponse
	err := c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		return safeAssign(v, &res)
	})

	return res, err
}

// Unix 发送数据
func (c *Client) SendUnixWithContext(ctx context.Context, req ua.Request, h func(interface{}) error) error {
	stats.Client().Add("Send", 1)
	err := c.sendUnixWithTimeout(ctx, req, c.cfg.sechan.RequestTimeout, h)
	stats.RecordError(err)
	return err
}

// Unix 超时发送数据
func (c *Client) sendUnixWithTimeout(cxt context.Context, req ua.Request, timeout time.Duration, h func(v interface{}) error) error {
	if c.SecureChannelUnix() == nil {
		return ua.StatusBadServerNotConnected
	}
	var authToken *ua.NodeID
	if s := c.Session(); s != nil {
		authToken = s.resp.AuthenticationToken
	}
	return c.SecureChannelUnix().SendRequestWithTimeoutWithContext(cxt, req, authToken, timeout, h)

}

// Unix 链接创建
func (c *Client) ConnectUnix(ctx context.Context) (err error) {
	if c.SecureChannelUnix() != nil {
		return errors.Errorf("already connected")
	}
	c.setState(Connecting)
	if err := c.DialUnix(ctx); err != nil {
		stats.RecordError(err)
		return err
	}

	s, err := c.CreateSessionUnixWithContext(ctx, c.cfg.session)
	if err != nil {
		c.CloseUnixWithContext(ctx)
		stats.RecordError(err)

		return err
	}

	if err := c.ActivateSessionUnixWithContext(ctx, s); err != nil {
		c.CloseUnixWithContext(ctx)
		stats.RecordError(err)

		return err
	}
	c.setState(Connected)

	mctx, mcancel := context.WithCancel(context.Background())
	c.mcancel = mcancel
	c.monitorOnce.Do(func() {
		go c.monitor(mctx)
		go c.monitorSubscriptionsUnix(mctx)
	})

	// todo(fs): we might need to guard this with an option in case of a broken
	// todo(fs): server. For the sake of simplicity we left the option out but
	// todo(fs): see the discussion in https://github.com/gopcua/opcua/pull/512
	// todo(fs): and you should find a commit that implements this option.
	if err := c.UpdateNamespacesUnixWithContext(ctx); err != nil {
		c.CloseUnixWithContext(ctx)
		stats.RecordError(err)

		return err
	}

	return nil
}

func (c *Client) DialUnix(ctx context.Context) error {
	stats.Client().Add("DialUnix", 1)
	var err error
	if c.SecureChannelUnix() != nil {
		return errors.Errorf("secure channel already connected")
	}
	if err != nil {
		return err
	}
	var d = NewDialer(c.cfg)

	c.connUnix, err = d.DialUnix(ctx, c.endpointURL)
	if err != nil {
		return err
	}

	sc, err := uasc.NewSecureChannelUnix(c.endpointURL, c.connUnix, c.cfg.sechan, c.sechanErr)
	if err != nil {
		c.conn.Close()
		return err
	}
	if err := sc.Open(ctx); err != nil {
		c.conn.Close()
		return err
	}
	c.setSecureChannelUnix(sc)

	return nil
}

func (c *Client) SecureChannelUnix() *uasc.SecureChannelUnix {
	return c.atomicSechanUnix.Load().(*uasc.SecureChannelUnix)
}

func (c *Client) setSecureChannelUnix(sc *uasc.SecureChannelUnix) {
	c.atomicSechanUnix.Store(sc)
	stats.Client().Add("SecureChannelUnix", 1)
}

func (c *Client) ActivateSessionUnixWithContext(ctx context.Context, s *Session) error {
	if c.SecureChannelUnix() == nil {
		return ua.StatusBadServerNotConnected
	}
	stats.Client().Add("ActivateSession", 1)
	sig, sigAlg, err := c.SecureChannelUnix().NewSessionSignature(s.serverCertificate, s.serverNonce)
	if err != nil {
		log.Printf("error creating session signature: %s", err)
		return nil
	}

	switch tok := s.cfg.UserIdentityToken.(type) {
	case *ua.AnonymousIdentityToken:
		// nothing to do

	case *ua.UserNameIdentityToken:
		pass, passAlg, err := c.SecureChannelUnix().EncryptUserPassword(s.cfg.AuthPolicyURI, s.cfg.AuthPassword, s.serverCertificate, s.serverNonce)
		if err != nil {
			log.Printf("error encrypting user password: %s", err)
			return err
		}
		tok.Password = pass
		tok.EncryptionAlgorithm = passAlg

	case *ua.X509IdentityToken:
		tokSig, tokSigAlg, err := c.SecureChannelUnix().NewUserTokenSignature(s.cfg.AuthPolicyURI, s.serverCertificate, s.serverNonce)
		if err != nil {
			log.Printf("error creating session signature: %s", err)
			return err
		}
		s.cfg.UserTokenSignature = &ua.SignatureData{
			Algorithm: tokSigAlg,
			Signature: tokSig,
		}

	case *ua.IssuedIdentityToken:
		tok.EncryptionAlgorithm = ""
	}

	req := &ua.ActivateSessionRequest{
		ClientSignature: &ua.SignatureData{
			Algorithm: sigAlg,
			Signature: sig,
		},
		ClientSoftwareCertificates: nil,
		LocaleIDs:                  s.cfg.LocaleIDs,
		UserIdentityToken:          ua.NewExtensionObject(s.cfg.UserIdentityToken),
		UserTokenSignature:         s.cfg.UserTokenSignature,
	}
	return c.SecureChannelUnix().SendRequestWithContext(ctx, req, s.resp.AuthenticationToken, func(v interface{}) error {
		var res *ua.ActivateSessionResponse
		if err := safeAssign(v, &res); err != nil {
			return err
		}

		// save the nonce for the next request
		s.serverNonce = res.ServerNonce

		// close the previous session
		//
		// https://github.com/gopcua/opcua/issues/474
		//
		// We decided not to check the error of CloseSession() since we
		// can't do much about it anyway and it creates a race in the
		// re-connection logic.
		c.CloseSession()

		c.setSession(s)
		return nil
	})
}

// Unix 创建会话
func (c *Client) CreateSessionUnixWithContext(ctx context.Context, cfg *uasc.SessionConfig) (*Session, error) {
	if c.SecureChannelUnix() == nil {
		return nil, ua.StatusBadServerNotConnected
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	name := cfg.SessionName
	if name == "" {
		name = fmt.Sprintf("gopcua-%d", time.Now().UnixNano())
	}

	req := &ua.CreateSessionRequest{
		ClientDescription:       cfg.ClientDescription,
		EndpointURL:             c.endpointURL,
		SessionName:             name,
		ClientNonce:             nonce,
		ClientCertificate:       c.cfg.sechan.Certificate,
		RequestedSessionTimeout: float64(cfg.SessionTimeout / time.Millisecond),
	}

	var s *Session
	// for the CreateSessionRequest the authToken is always nil.
	// use c.SecureChannel().SendRequest() to enforce this.
	err := c.SecureChannelUnix().SendRequestWithContext(ctx, req, nil, func(v interface{}) error {
		var res *ua.CreateSessionResponse
		if err := safeAssign(v, &res); err != nil {
			return err
		}

		err := c.SecureChannelUnix().VerifySessionSignature(res.ServerCertificate, nonce, res.ServerSignature.Signature)
		if err != nil {
			log.Printf("error verifying session signature: %s", err)
			return nil
		}

		// Ensure we have a valid identity token that the server will accept before trying to activate a session
		if c.cfg.session.UserIdentityToken == nil {
			opt := AuthAnonymous()
			opt(c.cfg)

			p := anonymousPolicyID(res.ServerEndpoints)
			opt = AuthPolicyID(p)
			opt(c.cfg)
		}

		s = &Session{
			cfg:               cfg,
			resp:              res,
			serverNonce:       res.ServerNonce,
			serverCertificate: res.ServerCertificate,
		}

		return nil
	})
	return s, err
}

// Unix 订阅
func (c *Client) SubscribeUnixWithContext(ctx context.Context, params *SubscriptionParameters, notifyCh chan<- *PublishNotificationData) (*Subscription, error) {
	stats.Client().Add("SubscribeUnix", 1)

	if params == nil {
		params = &SubscriptionParameters{}
	}

	params.setDefaults()
	req := &ua.CreateSubscriptionRequest{
		RequestedPublishingInterval: float64(params.Interval / time.Millisecond),
		RequestedLifetimeCount:      params.LifetimeCount,
		RequestedMaxKeepAliveCount:  params.MaxKeepAliveCount,
		PublishingEnabled:           true,
		MaxNotificationsPerPublish:  params.MaxNotificationsPerPublish,
		Priority:                    params.Priority,
	}

	var res *ua.CreateSubscriptionResponse
	err := c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		return safeAssign(v, &res)
	})
	if err != nil {
		return nil, err
	}
	if res.ResponseHeader.ServiceResult != ua.StatusOK {
		return nil, res.ResponseHeader.ServiceResult
	}

	stats.Subscription().Add("Count", 1)

	// start the publish loop if it isn't already running
	c.resumech <- struct{}{}

	sub := &Subscription{
		SubscriptionID:            res.SubscriptionID,
		RevisedPublishingInterval: time.Duration(res.RevisedPublishingInterval) * time.Millisecond,
		RevisedLifetimeCount:      res.RevisedLifetimeCount,
		RevisedMaxKeepAliveCount:  res.RevisedMaxKeepAliveCount,
		Notifs:                    notifyCh,
		items:                     make(map[uint32]*monitoredItem),
		params:                    params,
		nextSeq:                   1,
		c:                         c,
	}

	c.subMux.Lock()
	defer c.subMux.Unlock()

	if sub.SubscriptionID == 0 || c.subs[sub.SubscriptionID] != nil {
		// this should not happen and is usually indicative of a server bug
		// see: Part 4 Section 5.13.2.2, Table 88 – CreateSubscription Service Parameters
		return nil, ua.StatusBadSubscriptionIDInvalid
	}

	c.subs[sub.SubscriptionID] = sub
	c.updatePublishTimeout_NeedsSubMuxRLock()
	return sub, nil
}

// Unix 获取历史数据
func (c *Client) HistoryReadRawModifiedUnixWithContext(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadRawModifiedDetails) (*ua.HistoryReadResponse, error) {
	stats.Client().Add("HistoryReadRawModified", 1)
	stats.Client().Add("HistoryReadValueID", int64(len(nodes)))

	// Part 4, 5.10.3 HistoryRead
	req := &ua.HistoryReadRequest{
		TimestampsToReturn: ua.TimestampsToReturnBoth,
		NodesToRead:        nodes,
		// Part 11, 6.4 HistoryReadDetails parameters
		HistoryReadDetails: &ua.ExtensionObject{
			TypeID:       ua.NewFourByteExpandedNodeID(0, id.ReadRawModifiedDetails_Encoding_DefaultBinary),
			EncodingMask: ua.ExtensionObjectBinary,
			Value:        details,
		},
	}

	var res *ua.HistoryReadResponse
	err := c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		return safeAssign(v, &res)
	})
	return res, err
}

// Unix 方法调用
func (c *Client) CallUnixWithContext(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	stats.Client().Add("CallUnix", 1)

	creq := &ua.CallRequest{
		MethodsToCall: []*ua.CallMethodRequest{req},
	}
	var res *ua.CallResponse
	err := c.SendUnixWithContext(ctx, creq, func(v interface{}) error {
		return safeAssign(v, &res)
	})
	if err != nil {
		return nil, err
	}
	if len(res.Results) != 1 {
		return nil, ua.StatusBadUnknownResponse
	}
	return res.Results[0], nil
}

// Unix 修改数据
func (c *Client) WriteUnixWithContext(ctx context.Context, req *ua.WriteRequest) (*ua.WriteResponse, error) {
	stats.Client().Add("WriteUnix", 1)
	stats.Client().Add("NodesToWrite", int64(len(req.NodesToWrite)))

	var res *ua.WriteResponse
	err := c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		return safeAssign(v, &res)
	})
	return res, err
}
func (c *Client) UpdateNamespacesUnixWithContext(ctx context.Context) error {
	stats.Client().Add("UpdateNamespacesUnix", 1)
	ns, err := c.NamespaceArrayUnixWithContext(ctx)

	if err != nil {
		return err
	}
	c.setNamespaces(ns)
	return nil
}

func (c *Client) NamespaceArrayUnixWithContext(ctx context.Context) ([]string, error) {
	stats.Client().Add("NamespaceArrayUnix", 1)
	node := c.Node(ua.NewNumericNodeID(0, id.Server_NamespaceArray))
	v, err := node.ValueUnixWithContext(ctx)
	if err != nil {
		return nil, err
	}

	ns, ok := v.Value().([]string)
	if !ok {
		return nil, errors.Errorf("error fetching namespace array. id=%d, type=%T", v.Type(), v.Value())
	}
	return ns, nil
}

func (n *Node) ValueUnixWithContext(ctx context.Context) (*ua.Variant, error) {
	return n.AttributeUnixWithContext(ctx, ua.AttributeIDValue)
}

func (n *Node) AttributeUnixWithContext(ctx context.Context, attrID ua.AttributeID) (*ua.Variant, error) {
	rv := &ua.ReadValueID{NodeID: n.ID, AttributeID: attrID}
	req := &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{rv}}
	res, err := n.c.ReadUnixWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(res.Results) == 0 {
		// #188: we return StatusBadUnexpectedError because it is unclear, under what
		// circumstances the server would return no error and no results in the response
		return nil, ua.StatusBadUnexpectedError
	}
	value := res.Results[0].Value
	if res.Results[0].Status != ua.StatusOK {
		return value, res.Results[0].Status
	}
	return value, nil
}

func (c *Client) ReadUnixWithContext(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error) {
	stats.Client().Add("ReadUnix", 1)
	stats.Client().Add("NodesToRead", int64(len(req.NodesToRead)))

	// clone the request and the ReadValueIDs to set defaults without
	// manipulating them in-place.
	req = cloneReadRequest(req)

	var res *ua.ReadResponse
	err := c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		err := safeAssign(v, &res)

		// If the client cannot decode an extension object then its
		// value will be nil. However, since the EO was known to the
		// server the StatusCode for that data value will be OK. We
		// therefore check for extension objects with nil values and set
		// the status code to StatusBadDataTypeIDUnknown.
		if err == nil {
			for _, dv := range res.Results {
				if dv.Value == nil {
					continue
				}
				val := dv.Value.Value()
				if eo, ok := val.(*ua.ExtensionObject); ok && eo.Value == nil {
					dv.Status = ua.StatusBadDataTypeIDUnknown
				}
			}
		}

		return err
	})
	return res, err
}

func (c *Client) CloseUnixWithContext(ctx context.Context) error {
	stats.Client().Add("Close", 1)

	// try to close the session but ignore any error
	// so that we close the underlying channel and connection.
	c.CloseSessionWithContext(ctx)
	c.setState(Closed)

	if c.mcancel != nil {
		c.mcancel()
	}
	if c.SecureChannelUnix() != nil {
		c.SecureChannelUnix().Close()
	}

	// https://github.com/gopcua/opcua/pull/462
	//
	// do not close the c.sechanErr channel since it leads to
	// race conditions and it gets garbage collected anyway.
	// There is nothing we can do with this error while
	// shutting down the client so I think it is safe to ignore
	// them.

	// close the connection but ignore the error since there isn't
	// anything we can do about it anyway
	if c.connUnix != nil {
		c.connUnix.Close()
	}

	return nil
}

func (s *Subscription) MonitorUnixWithContext(ctx context.Context, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemCreateRequest) (*ua.CreateMonitoredItemsResponse, error) {
	stats.Subscription().Add("MonitorUnix", 1)
	stats.Subscription().Add("MonitoredItems", int64(len(items)))

	// Part 4, 5.12.2.2 CreateMonitoredItems Service Parameters
	req := &ua.CreateMonitoredItemsRequest{
		SubscriptionID:     s.SubscriptionID,
		TimestampsToReturn: ts,
		ItemsToCreate:      items,
	}

	var res *ua.CreateMonitoredItemsResponse
	err := s.c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		return safeAssign(v, &res)
	})

	if err != nil {
		return nil, err
	}

	// store monitored items
	s.itemsMu.Lock()
	for i, item := range items {
		result := res.Results[i]
		s.items[result.MonitoredItemID] = &monitoredItem{
			req: item,
			res: result,
			ts:  ts,
		}
	}
	s.itemsMu.Unlock()

	return res, err
}

func (n *Node) AttributesUnixWithContext(ctx context.Context, attrID ...ua.AttributeID) ([]*ua.DataValue, error) {
	req := &ua.ReadRequest{}
	for _, id := range attrID {
		rv := &ua.ReadValueID{NodeID: n.ID, AttributeID: id}
		req.NodesToRead = append(req.NodesToRead, rv)
	}
	res, err := n.c.ReadUnixWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	return res.Results, nil
}

func (n *Node) ReferencedNodesUnixWithContext(ctx context.Context, refs uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) ([]*Node, error) {
	if refs == 0 {
		refs = id.References
	}
	var nodes []*Node
	res, err := n.ReferencesUnixWithContext(ctx, refs, dir, mask, includeSubtypes)
	if err != nil {
		return nil, err
	}
	for _, r := range res {
		nodes = append(nodes, n.c.Node(r.NodeID.NodeID))
	}
	return nodes, nil
}

func (n *Node) ReferencesUnixWithContext(ctx context.Context, refType uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) ([]*ua.ReferenceDescription, error) {
	if refType == 0 {
		refType = id.References
	}
	if mask == 0 {
		mask = ua.NodeClassAll
	}

	desc := &ua.BrowseDescription{
		NodeID:          n.ID,
		BrowseDirection: dir,
		ReferenceTypeID: ua.NewNumericNodeID(0, refType),
		IncludeSubtypes: includeSubtypes,
		NodeClassMask:   uint32(mask),
		ResultMask:      uint32(ua.BrowseResultMaskAll),
	}

	req := &ua.BrowseRequest{
		View: &ua.ViewDescription{
			ViewID: ua.NewTwoByteNodeID(0),
		},
		RequestedMaxReferencesPerNode: 0,
		NodesToBrowse:                 []*ua.BrowseDescription{desc},
	}

	resp, err := n.c.BrowseUnixWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	return n.browseUnixNext(ctx, resp.Results)
}
func (c *Client) BrowseUnixWithContext(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error) {
	stats.Client().Add("Browse", 1)
	stats.Client().Add("NodesToBrowse", int64(len(req.NodesToBrowse)))

	// clone the request and the NodesToBrowse to set defaults without
	// manipulating them in-place.
	req = cloneBrowseRequest(req)

	var res *ua.BrowseResponse
	err := c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		return safeAssign(v, &res)
	})
	return res, err
}

func (n *Node) browseUnixNext(ctx context.Context, results []*ua.BrowseResult) ([]*ua.ReferenceDescription, error) {
	refs := results[0].References
	for len(results[0].ContinuationPoint) > 0 {
		req := &ua.BrowseNextRequest{
			ContinuationPoints:        [][]byte{results[0].ContinuationPoint},
			ReleaseContinuationPoints: false,
		}
		resp, err := n.c.BrowseNextWithContext(ctx, req)
		if err != nil {
			return nil, err
		}
		results = resp.Results
		refs = append(refs, results[0].References...)
	}
	return refs, nil
}

func (c *Client) BrowseNextUnixWithContext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error) {
	stats.Client().Add("BrowseNext", 1)

	var res *ua.BrowseNextResponse
	err := c.SendUnixWithContext(ctx, req, func(v interface{}) error {
		return safeAssign(v, &res)
	})
	return res, err
}

//开启订阅事件
func (c *Client) monitorSubscriptionsUnix(ctx context.Context) {
	dlog := debug.NewPrefixLogger("sub: ")
	defer dlog.Print("done")

publish:
	for {
		select {
		case <-ctx.Done():
			dlog.Println("ctx.Done()")
			return

		case <-c.resumech:
			dlog.Print("resume")
			// ignore since not paused

		case <-c.pausech:
			dlog.Print("pause")
			for {
				select {
				case <-ctx.Done():
					dlog.Print("pause: ctx.Done()")
					return

				case <-c.resumech:
					dlog.Print("pause: resume")
					continue publish

				case <-c.pausech:
					dlog.Print("pause: pause")
					// ignore since already paused
				}
			}

		default:
			// send publish request and handle response
			if err := c.publishUnix(ctx); err != nil {
				dlog.Print("error: ", err.Error())
				c.pauseSubscriptions(ctx)
			}
		}
	}
}

//处理订阅
func (c *Client) sendPublishUnixRequest(ctx context.Context) (*ua.PublishResponse, error) {
	dlog := debug.NewPrefixLogger("publish: ")

	c.subMux.RLock()
	req := &ua.PublishRequest{
		SubscriptionAcknowledgements: c.pendingAcks,
	}
	if req.SubscriptionAcknowledgements == nil {
		req.SubscriptionAcknowledgements = []*ua.SubscriptionAcknowledgement{}
	}
	c.subMux.RUnlock()

	dlog.Printf("PublishRequest: %s", debug.ToJSON(req))
	var res *ua.PublishResponse
	err := c.sendUnixWithTimeout(ctx, req, c.publishTimeout(), func(v interface{}) error {
		return safeAssign(v, &res)
	})
	stats.RecordError(err)
	dlog.Printf("PublishResponse: %s", debug.ToJSON(res))
	return res, err
}

//获取订阅数据
func (c *Client) publishUnix(ctx context.Context) error {
	dlog := debug.NewPrefixLogger("publish: ")

	c.subMux.RLock()
	dlog.Printf("pendingAcks=%s", debug.ToJSON(c.pendingAcks))
	c.subMux.RUnlock()

	// send the next publish request
	// note that res contains data even if an error was returned
	res, err := c.sendPublishUnixRequest(ctx)
	stats.RecordError(err)
	switch {
	case err == io.EOF:
		dlog.Printf("eof: pausing publish loop")
		return err

	case err == ua.StatusBadSessionNotActivated:
		dlog.Printf("error: session not active. pausing publish loop")
		return err

	case err == ua.StatusBadServerNotConnected:
		dlog.Printf("error: no connection. pausing publish loop")
		return err

	case err == ua.StatusBadSequenceNumberUnknown:
		// todo(fs): this should only happen per in the status codes
		// todo(fs): lets log this here to see
		dlog.Printf("error: this should only happen when ACK'ing results: %s", err)

	case err == ua.StatusBadTooManyPublishRequests:
		// todo(fs): we have sent too many publish requests
		// todo(fs): we need to slow down
		dlog.Printf("error: sleeping for one second: %s", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}

	case err == ua.StatusBadTimeout:
		// ignore and continue the loop
		dlog.Printf("error: ignoring: %s", err)

	case err == ua.StatusBadNoSubscription:
		// All subscriptions have been deleted, but the publishing loop is still running
		// We should pause publishing until a subscription has been created
		dlog.Printf("error: no subscriptions but the publishing loop is still running: %s", err)
		return err

	case err != nil && res != nil:
		// irrecoverable error
		// todo(fs): do we need to stop and forget the subscription?
		if res.SubscriptionID == 0 {
			c.notifyAllSubscriptionsOfError(ctx, err)
		} else {
			c.notifySubscriptionOfError(ctx, res.SubscriptionID, err)
		}
		dlog.Printf("error: %s", err)
		return err

	case err != nil:
		dlog.Printf("error: unexpected error. Do we need to stop the publish loop?: %s", err)
		return err

	default:
		c.subMux.Lock()
		// handle pending acks for all subscriptions
		c.handleAcks_NeedsSubMuxLock(res.Results)

		sub, ok := c.subs[res.SubscriptionID]
		if !ok {
			c.subMux.Unlock()
			// todo(fs): should we return an error here?
			dlog.Printf("error: unknown subscription %d", res.SubscriptionID)
			return nil
		}

		// handle the publish response for a specific subscription
		c.handleNotification_NeedsSubMuxLock(ctx, sub, res)
		c.subMux.Unlock()

		c.notifySubscription(ctx, sub, res.NotificationMessage)
		dlog.Printf("notif: %d", res.NotificationMessage.SequenceNumber)
	}

	return nil
}
