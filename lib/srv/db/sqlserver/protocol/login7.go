package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/gravitational/trace"
)

type Login7Packet struct {
	Packet   Packet
	Fields   Login7PacketFields
	Data     []byte
	User     string
	Database string
}

type Login7PacketFields struct {
	Length        uint32
	TDSVersion    uint32
	PacketSize    uint32
	ClientProgVer uint32
	ClientPID     uint32
	ConnectionID  uint32

	OptionFlags1 uint8
	OptionFlags2 uint8
	TypeFlags    uint8
	OptionFlags3 uint8

	ClientTimezone int32
	ClientLCID     uint32

	IbHostName        uint16
	CchHostName       uint16
	IbUserName        uint16
	CchUserName       uint16
	IbPassword        uint16
	CchPassword       uint16
	IbAppName         uint16
	CchAppName        uint16
	IbServerName      uint16
	CchServerName     uint16
	IbUnused          uint16
	CbUnused          uint16
	IbCltIntName      uint16
	CchCltIntName     uint16
	IbLanguage        uint16
	CchLanguage       uint16
	IbDatabase        uint16 // offset
	CchDatabase       uint16 // length
	ClientID          [6]byte
	IbSSPI            uint16
	CbSSPI            uint16
	IbAtchDBFile      uint16
	CchAtchDBFile     uint16
	IbChangePassword  uint16
	CchChangePassword uint16
	CbSSPILong        uint32
}

func ReadLogin7Packet(conn net.Conn) (*Login7Packet, error) {
	pkt, err := ReadPacket(conn)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	fmt.Printf("==> Parsing LOGIN7 packet length: %v\n", pkt.PacketHeader.Length)
	if pkt.Type != PacketTypeLogin7 {
		return nil, trace.BadParameter("expected LOGIN7 packet, got: %#v", pkt)
	}
	var fields Login7PacketFields
	buf := bytes.NewBuffer(pkt.Data)
	err = binary.Read(buf, binary.LittleEndian, &fields)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	p := &Login7Packet{
		Packet: *pkt,
		Fields: fields,
		Data:   buf.Bytes(), // Remaining unread portion of buffer is the login7 data.
	}
	p.Database, err = mssql.ParseUCS2String(pkt.Data[p.Fields.IbDatabase : p.Fields.IbDatabase+p.Fields.CchDatabase*2])
	if err != nil {
		return nil, trace.Wrap(err)
	}
	p.User, err = mssql.ParseUCS2String(pkt.Data[p.Fields.IbUserName : p.Fields.IbUserName+p.Fields.CchUserName*2])
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return p, nil
}

func WriteLogin7Response(conn net.Conn, tokens [][]byte) error {
	var data []byte

	for _, token := range tokens {
		data = append(data, token...)
	}

	pkt, err := makePacket(PacketTypeResponse, data)
	if err != nil {
		return trace.Wrap(err)
	}

	fmt.Println("=== SENT LOGIN7 PACKET ===")
	fmt.Println(hex.Dump(pkt))
	fmt.Println("=======================")

	// Write packet to connection.
	if _, err := conn.Write(pkt); err != nil {
		return trace.Wrap(err)
	}

	return nil
}
