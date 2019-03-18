// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ua

import (
	"testing"
	"time"
)

func TestFindServersRequest(t *testing.T) {
	cases := []CodecTestCase{
		{
			Name: "no-locales, no-uris",
			Struct: NewFindServersRequest(
				NewRequestHeader(
					NewByteStringNodeID(0x00, []byte{
						0x08, 0x22, 0x87, 0x62, 0xba, 0x81, 0xe1, 0x11,
						0xa6, 0x43, 0xf8, 0x77, 0x7b, 0xc6, 0x2f, 0xc8,
					}),
					time.Date(2018, time.August, 10, 23, 0, 0, 0, time.UTC),
					1, 0, 0, "", NewNullExtensionObject(),
				),
				"opc.tcp://wow.its.easy:11111/UA/Server",
				nil,
				// []string{},
				// todo(fs): this looks like a bug since providing an empty string
				// todo(fs): actually creates an array of length 1 and not zero.
				// "",
				nil,
			),
			Bytes: []byte{
				// AuthenticationToken
				0x05, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08,
				0x22, 0x87, 0x62, 0xba, 0x81, 0xe1, 0x11, 0xa6,
				0x43, 0xf8, 0x77, 0x7b, 0xc6, 0x2f, 0xc8,
				// Timestamp
				0x00, 0x98, 0x67, 0xdd, 0xfd, 0x30, 0xd4, 0x01,
				// RequestHandle
				0x01, 0x00, 0x00, 0x00,
				// ReturnDiagnostics
				0x00, 0x00, 0x00, 0x00,
				// AuditEntryID
				0xff, 0xff, 0xff, 0xff,
				// TimeoutHint
				0x00, 0x00, 0x00, 0x00,
				// AdditionalHeader
				0x00, 0x00, 0x00,
				// EndpointURL
				0x26, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e,
				0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x6f,
				0x77, 0x2e, 0x69, 0x74, 0x73, 0x2e, 0x65, 0x61,
				0x73, 0x79, 0x3a, 0x31, 0x31, 0x31, 0x31, 0x31,
				0x2f, 0x55, 0x41, 0x2f, 0x53, 0x65, 0x72, 0x76,
				0x65, 0x72,
				// LocaleIDs
				0xff, 0xff, 0xff, 0xff,
				// ServerURIs
				0xff, 0xff, 0xff, 0xff,
			},
		},
	}
	RunCodecTest(t, cases)
}
