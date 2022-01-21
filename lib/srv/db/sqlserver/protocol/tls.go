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
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/gravitational/trace"
)

func TLSHandshake(conn net.Conn, conf *tls.Config) (*tls.Conn, error) {
	handshakeConn := &tlsHandshakeConn{c: conn}

	passConn := &passthroughConn{handshakeConn}

	tlsConn := tls.Server(passConn, conf)

	if err := tlsConn.Handshake(); err != nil {
		return nil, trace.Wrap(err)
	}

	passConn.c = conn

	return tlsConn, nil
}

type tlsHandshakeConn struct {
	c net.Conn
	b bytes.Buffer
}

func (c *tlsHandshakeConn) Read(b []byte) (int, error) {
	// First read remainder from the buffer.
	if c.b.Len() > 0 {
		return c.b.Read(b)
	}

	// Read a new packet.
	pkt, err := ReadPacket(c.c)
	if err != nil {
		return 0, trace.Wrap(err)
	}
	if pkt.Type != PacketTypePreLogin {
		return 0, trace.BadParameter("expected PRELOGIN packet, got: %#v", pkt.Type)
	}
	c.b.Write(pkt.Data) // TODO handle error

	return c.b.Read(b)
}

func (c *tlsHandshakeConn) Write(b []byte) (int, error) {
	// TLS payload should be sent as PRELOGIN packets.
	pkt, err := makePacket(PacketTypePreLogin, b)
	if err != nil {
		return 0, trace.Wrap(err)
	}

	fmt.Printf("=== WRITING TLS PACKET LEN: %v ===\n", len(pkt))
	fmt.Println(hex.Dump(pkt))
	fmt.Println("=======================")

	return c.c.Write(pkt)
}

func (c *tlsHandshakeConn) Close() error {
	return c.c.Close()
}

func (c *tlsHandshakeConn) LocalAddr() net.Addr {
	return nil
}

func (c *tlsHandshakeConn) RemoteAddr() net.Addr {
	return nil
}

func (c *tlsHandshakeConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *tlsHandshakeConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *tlsHandshakeConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type passthroughConn struct {
	c net.Conn
}

func (c passthroughConn) Read(b []byte) (n int, err error) {
	return c.c.Read(b)
}

func (c passthroughConn) Write(b []byte) (n int, err error) {
	return c.c.Write(b)
}

func (c passthroughConn) Close() error {
	return c.c.Close()
}

func (c passthroughConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c passthroughConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c passthroughConn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

func (c passthroughConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c passthroughConn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}
