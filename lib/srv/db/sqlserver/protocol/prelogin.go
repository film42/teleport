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
	"encoding/hex"
	"fmt"
	"net"

	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/gravitational/trace"
)

type PreloginPacket struct {
	Packet Packet
}

func ReadPreloginPacket(conn net.Conn) (*PreloginPacket, error) {
	pkt, err := ReadPacket(conn)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if pkt.Type != PacketTypePreLogin {
		return nil, trace.BadParameter("expected PRELOGIN packet, got: %#v", pkt)
	}
	return &PreloginPacket{
		Packet: *pkt,
	}, nil
}

func WritePreloginResponse(conn net.Conn) error {
	options := map[uint8][]byte{
		preLoginOptionVersion:    preLoginVersion,
		preLoginOptionEncryption: {preLoginEncryptionRequired},
		preLoginOptionInstance:   {0x00},
		preLoginOptionThreadID:   {},
		preLoginOptionMARS:       {0x00},
	}

	var buf bytes.Buffer
	err := mssql.WritePreloginFields(&buf, options)
	if err != nil {
		return trace.Wrap(err)
	}

	pkt, err := makePacket(PacketTypeResponse, buf.Bytes())
	if err != nil {
		return trace.Wrap(err)
	}

	fmt.Println("=== SENT PRELOGIN PACKET ===")
	fmt.Println(hex.Dump(pkt))
	fmt.Println("=======================")

	_, err = conn.Write(pkt)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}
