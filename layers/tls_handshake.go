// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/google/gopacket"
)

// TLSType defines the type of data after the TLS Record
type TLSHandshakeType uint8

// TLSType known values.
const (
	TLSHandshakeUnknown     TLSHandshakeType = 0
	TLSHandshakeClientHello TLSHandshakeType = 1
	TLSHandshakeServerHello TLSHandshakeType = 2
)

type TLSHandshakeProtocol struct {
	HandshakeType TLSHandshakeType
	ServerName    string
}

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	TLSHandshakeProtocol
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	current := 0

	current = current + 1
	if data[0] != 0x1 {
		return nil
	}

	t.HandshakeType = TLSHandshakeClientHello

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28

	// Skip over session ID
	sessionIDLength := int(data[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(data[current]) << 8) + int(data[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(data[current])
	current += 1
	current += compressionMethodLength

	if current > len(data) {
		return nil
	}

	current += 2

	hostname := ""
	for current < len(data) && hostname == "" {
		extensionType := (int(data[current]) << 8) + int(data[current+1])
		current += 2

		extensionDataLength := (int(data[current]) << 8) + int(data[current+1])
		current += 2

		if extensionType == 0 {

			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := data[current]
			current += 1
			if nameType != 0 {
				return nil
			}
			nameLen := (int(data[current]) << 8) + int(data[current+1])
			current += 2
			hostname = string(data[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		return nil
	}

	t.ServerName = hostname

	return nil
}
