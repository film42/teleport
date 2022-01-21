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

const (
	// PacketTypeResponse is the packet type for server response messages.
	PacketTypeResponse uint8 = 0x04
	// PacketTypeLogin7 is the LOGIN7 packet type.
	PacketTypeLogin7 uint8 = 0x10
	// PacketTypePreLogin is the PRELOGIN packet type.
	PacketTypePreLogin uint8 = 0x12
)

const (
	preLoginOptionVersion    = 0x00
	preLoginOptionEncryption = 0x01
	preLoginOptionInstance   = 0x02
	preLoginOptionThreadID   = 0x03
	preLoginOptionMARS       = 0x04
)

// packetStatusLast indicates that the packet is the last in the request.
const packetStatusLast uint8 = 0x01

// packetHeaderSize is the size of the protocol packet header.
const packetHeaderSize = 8

// preLoginVersion is returned to the client as a part of PRELOGIN response.
var preLoginVersion = []uint8{0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00}

// preLoginEncryptionRequired is a PRELOGIN option indicating that TLS is required.
const preLoginEncryptionRequired = 0x03
