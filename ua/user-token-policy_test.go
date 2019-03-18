// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ua

import (
	"testing"
)

func TestUserTokenPolicy(t *testing.T) {
	cases := []CodecTestCase{
		{
			Struct: NewUserTokenPolicy(
				"1", UserTokenTypeAnonymous,
				"issued-token", "issuer-uri", "sec-uri",
			),
			Bytes: []byte{
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
			},
		},
	}
	RunCodecTest(t, cases)
}

func TestUserTokenPolicyArray(t *testing.T) {
	cases := []CodecTestCase{
		{
			Struct: []*UserTokenPolicy{
				NewUserTokenPolicy(
					"1", UserTokenTypeAnonymous,
					"issued-token", "issuer-uri", "sec-uri",
				),
				NewUserTokenPolicy(
					"1", UserTokenTypeAnonymous,
					"issued-token", "issuer-uri", "sec-uri",
				),
			},
			Bytes: []byte{
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
			},
		},
	}
	RunCodecTest(t, cases)
}
