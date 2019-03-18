// Copyright 2018-2019 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Code generated by cmd/service. DO NOT EDIT!

package ua

type RegisteredServer struct {
	ServerURI         string
	ProductURI        string
	ServerNames       []*LocalizedText
	ServerType        ApplicationType
	GatewayServerURI  string
	DiscoveryURLs     []string
	SemaphoreFilePath string
	IsOnline          bool
}
