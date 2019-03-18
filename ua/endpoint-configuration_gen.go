// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Code generated by cmd/service. DO NOT EDIT!

package ua

type EndpointConfiguration struct {
	OperationTimeout      int32
	UseBinaryEncoding     bool
	MaxStringLength       int32
	MaxByteStringLength   int32
	MaxArrayLength        int32
	MaxMessageSize        int32
	MaxBufferSize         int32
	ChannelLifetime       int32
	SecurityTokenLifetime int32
}
