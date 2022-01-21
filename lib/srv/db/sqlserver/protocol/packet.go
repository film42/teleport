/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/gravitational/trace"
)

// PacketHeader is a parsed form of a 8-byte SQL server protocol packet header.
//
// Note: the order of fields in the struct matters.
type PacketHeader struct {
	Type     uint8
	Status   uint8
	Length   uint16 // network byte order (big-endian)
	SPID     uint16 // network byte order (big-endian)
	PacketID uint8
	Window   uint8
}

// Marshal marshals the packet header to the wire protocol byte representation.
func (h *PacketHeader) Marshal() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, packetHeaderSize))
	if err := binary.Write(buf, binary.BigEndian, h); err != nil {
		return nil, trace.Wrap(err)
	}
	return buf.Bytes(), nil
}

type Packet struct {
	// Header
	PacketHeader

	// HeaderBytes contains packet header raw bytes.
	HeaderBytes []byte

	// Data (without header).
	Data []byte
}

// ReadPacket reads a single full packet from the provided connection.
func ReadPacket(conn io.Reader) (*Packet, error) {
	// Read 8-byte packet header.
	var headerBytes [packetHeaderSize]byte
	if _, err := io.ReadFull(conn, headerBytes[:]); err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	// Unmarshal packet header from the binary form.
	var header PacketHeader
	if err := binary.Read(bytes.NewReader(headerBytes[:]), binary.BigEndian, &header); err != nil {
		return nil, trace.Wrap(err)
	}

	// Read packet data. Packet length includes header.
	dataBytes := make([]byte, header.Length-packetHeaderSize)
	if _, err := io.ReadFull(conn, dataBytes); err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	fmt.Println("=== RECEIVED PACKET ===")
	fmt.Println(hex.Dump(append(headerBytes[:], dataBytes...)))
	fmt.Println("=======================")

	return &Packet{
		PacketHeader: header,
		HeaderBytes:  headerBytes[:],
		Data:         dataBytes,
	}, nil
}

// makePacket prepends header to the provided packet data.
func makePacket(pktType uint8, pktData []byte) ([]byte, error) {
	header := PacketHeader{
		Type:   pktType,
		Status: packetStatusLast,
		Length: uint16(packetHeaderSize + len(pktData)),
	}
	headerBytes, err := header.Marshal()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return append(headerBytes, pktData...), nil
}
