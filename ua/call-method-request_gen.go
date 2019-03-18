// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Code generated by cmd/service. DO NOT EDIT!

package ua

type CallMethodRequest struct {
	ObjectID       *NodeID
	MethodID       *NodeID
	InputArguments []*Variant
}
