// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ua

import (
	"testing"
)

func TestEndpointDescription(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name: "Normal",
			Struct: NewEndpointDescription(
				"ep-url",
				NewApplicationDescription(
					"app-uri", "prod-uri", "app-name", ApplicationTypeServer,
					"gw-uri", "prof-uri", []string{"discov-uri-1", "discov-uri-2"},
				),
				nil,
				MessageSecurityModeNone,
				"sec-uri",
				[]*UserTokenPolicy{
					NewUserTokenPolicy(
						"1", UserTokenTypeAnonymous,
						"issued-token", "issuer-uri", "sec-uri",
					),
					NewUserTokenPolicy(
						"1", UserTokenTypeAnonymous,
						"issued-token", "issuer-uri", "sec-uri",
					),
				},
				"trans-uri",
				0,
			),
			Bytes: []byte{
				// EndpointURI
				0x06, 0x00, 0x00, 0x00, 0x65, 0x70, 0x2d, 0x75, 0x72, 0x6c,
				// Server (ApplicationDescription)
				// ApplicationURI
				0x07, 0x00, 0x00, 0x00, 0x61, 0x70, 0x70, 0x2d, 0x75, 0x72, 0x69,
				// ProductURI
				0x08, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6f, 0x64, 0x2d, 0x75, 0x72, 0x69,
				// ApplicationName
				0x02, 0x08, 0x00, 0x00, 0x00, 0x61, 0x70, 0x70, 0x2d,
				0x6e, 0x61, 0x6d, 0x65,
				// ApplicationType
				0x00, 0x00, 0x00, 0x00,
				// GatewayServerURI
				0x06, 0x00, 0x00, 0x00, 0x67, 0x77, 0x2d, 0x75, 0x72, 0x69,
				// DiscoveryProfileURI
				0x08, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6f, 0x66, 0x2d, 0x75, 0x72, 0x69,
				// DiscoveryURIs
				0x02, 0x00, 0x00, 0x00,
				0x0c, 0x00, 0x00, 0x00, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x2d, 0x75, 0x72, 0x69, 0x2d, 0x31,
				0x0c, 0x00, 0x00, 0x00, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x2d, 0x75, 0x72, 0x69, 0x2d, 0x32,
				// ServerCertificate
				0xff, 0xff, 0xff, 0xff,
				// MessageSecurityMode
				0x01, 0x00, 0x00, 0x00,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// UserIdentityTokens
				// ArraySize
				0x02, 0x00, 0x00, 0x00,
				// PolicyID
				0x01, 0x00, 0x00, 0x00, 0x31,
				// TokenType
				0x00, 0x00, 0x00, 0x00,
				// IssuedTokenType
				0x0c, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
				// IssuerEndpointURI
				0x0a, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x2d, 0x75, 0x72, 0x69,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// PolicyID
				0x01, 0x00, 0x00, 0x00, 0x31,
				// TokenType
				0x00, 0x00, 0x00, 0x00,
				// IssuedTokenType
				0x0c, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
				// IssuerEndpointURI
				0x0a, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x2d, 0x75, 0x72, 0x69,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// TransportProfileURI
				0x09, 0x00, 0x00, 0x00, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x2d, 0x75, 0x72, 0x69,
				// SecurityLevel
				0x00,
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestEndpointDescriptionArray(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name: "Normal",
			Struct: []*EndpointDescription{
				NewEndpointDescription(
					"ep-url",
					NewApplicationDescription(
						"app-uri", "prod-uri", "app-name", ApplicationTypeServer,
						"gw-uri", "prof-uri", []string{"discov-uri-1", "discov-uri-2"},
					),
					nil,
					MessageSecurityModeNone,
					"sec-uri",
					[]*UserTokenPolicy{
						NewUserTokenPolicy(
							"1", UserTokenTypeAnonymous,
							"issued-token", "issuer-uri", "sec-uri",
						),
						NewUserTokenPolicy(
							"1", UserTokenTypeAnonymous,
							"issued-token", "issuer-uri", "sec-uri",
						),
					},
					"trans-uri",
					0,
				),
				NewEndpointDescription(
					"ep-url",
					NewApplicationDescription(
						"app-uri", "prod-uri", "app-name", ApplicationTypeServer,
						"gw-uri", "prof-uri", []string{"discov-uri-1", "discov-uri-2"},
					),
					nil,
					MessageSecurityModeNone,
					"sec-uri",
					[]*UserTokenPolicy{
						NewUserTokenPolicy(
							"1", UserTokenTypeAnonymous,
							"issued-token", "issuer-uri", "sec-uri",
						),
						NewUserTokenPolicy(
							"1", UserTokenTypeAnonymous,
							"issued-token", "issuer-uri", "sec-uri",
						),
					},
					"trans-uri",
					0,
				),
			},
			Bytes: []byte{
				// ArraySize
				0x02, 0x00, 0x00, 0x00,
				// EndpointURI
				0x06, 0x00, 0x00, 0x00, 0x65, 0x70, 0x2d, 0x75, 0x72, 0x6c,
				// Server (ApplicationDescription)
				// ApplicationURI
				0x07, 0x00, 0x00, 0x00, 0x61, 0x70, 0x70, 0x2d, 0x75, 0x72, 0x69,
				// ProductURI
				0x08, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6f, 0x64, 0x2d, 0x75, 0x72, 0x69,
				// ApplicationName
				0x02, 0x08, 0x00, 0x00, 0x00, 0x61, 0x70, 0x70, 0x2d,
				0x6e, 0x61, 0x6d, 0x65,
				// ApplicationType
				0x00, 0x00, 0x00, 0x00,
				// GatewayServerURI
				0x06, 0x00, 0x00, 0x00, 0x67, 0x77, 0x2d, 0x75, 0x72, 0x69,
				// DiscoveryProfileURI
				0x08, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6f, 0x66, 0x2d, 0x75, 0x72, 0x69,
				// DiscoveryURIs
				0x02, 0x00, 0x00, 0x00,
				0x0c, 0x00, 0x00, 0x00, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x2d, 0x75, 0x72, 0x69, 0x2d, 0x31,
				0x0c, 0x00, 0x00, 0x00, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x2d, 0x75, 0x72, 0x69, 0x2d, 0x32,
				// ServerCertificate
				0xff, 0xff, 0xff, 0xff,
				// MessageSecurityMode
				0x01, 0x00, 0x00, 0x00,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// UserIdentityTokens
				// ArraySize
				0x02, 0x00, 0x00, 0x00,
				// PolicyID
				0x01, 0x00, 0x00, 0x00, 0x31,
				// TokenType
				0x00, 0x00, 0x00, 0x00,
				// IssuedTokenType
				0x0c, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
				// IssuerEndpointURI
				0x0a, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x2d, 0x75, 0x72, 0x69,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// PolicyID
				0x01, 0x00, 0x00, 0x00, 0x31,
				// TokenType
				0x00, 0x00, 0x00, 0x00,
				// IssuedTokenType
				0x0c, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
				// IssuerEndpointURI
				0x0a, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x2d, 0x75, 0x72, 0x69,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// TransportProfileURI
				0x09, 0x00, 0x00, 0x00, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x2d, 0x75, 0x72, 0x69,
				// SecurityLevel
				0x00,
				// EndpointURI
				0x06, 0x00, 0x00, 0x00, 0x65, 0x70, 0x2d, 0x75, 0x72, 0x6c,
				// Server (ApplicationDescription)
				// ApplicationURI
				0x07, 0x00, 0x00, 0x00, 0x61, 0x70, 0x70, 0x2d, 0x75, 0x72, 0x69,
				// ProductURI
				0x08, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6f, 0x64, 0x2d, 0x75, 0x72, 0x69,
				// ApplicationName
				0x02, 0x08, 0x00, 0x00, 0x00, 0x61, 0x70, 0x70, 0x2d,
				0x6e, 0x61, 0x6d, 0x65,
				// ApplicationType
				0x00, 0x00, 0x00, 0x00,
				// GatewayServerURI
				0x06, 0x00, 0x00, 0x00, 0x67, 0x77, 0x2d, 0x75, 0x72, 0x69,
				// DiscoveryProfileURI
				0x08, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6f, 0x66, 0x2d, 0x75, 0x72, 0x69,
				// DiscoveryURIs
				0x02, 0x00, 0x00, 0x00,
				0x0c, 0x00, 0x00, 0x00, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x2d, 0x75, 0x72, 0x69, 0x2d, 0x31,
				0x0c, 0x00, 0x00, 0x00, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x2d, 0x75, 0x72, 0x69, 0x2d, 0x32,
				// ServerCertificate
				0xff, 0xff, 0xff, 0xff,
				// MessageSecurityMode
				0x01, 0x00, 0x00, 0x00,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// UserIdentityTokens
				// ArraySize
				0x02, 0x00, 0x00, 0x00,
				// PolicyID
				0x01, 0x00, 0x00, 0x00, 0x31,
				// TokenType
				0x00, 0x00, 0x00, 0x00,
				// IssuedTokenType
				0x0c, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
				// IssuerEndpointURI
				0x0a, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x2d, 0x75, 0x72, 0x69,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// PolicyID
				0x01, 0x00, 0x00, 0x00, 0x31,
				// TokenType
				0x00, 0x00, 0x00, 0x00,
				// IssuedTokenType
				0x0c, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
				// IssuerEndpointURI
				0x0a, 0x00, 0x00, 0x00, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x2d, 0x75, 0x72, 0x69,
				// SecurityPolicyURI
				0x07, 0x00, 0x00, 0x00, 0x73, 0x65, 0x63, 0x2d, 0x75, 0x72, 0x69,
				// TransportProfileURI
				0x09, 0x00, 0x00, 0x00, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x2d, 0x75, 0x72, 0x69,
				// SecurityLevel
				0x00,
			},
		},
	}
	RunCodecTest(t, cases)
}
