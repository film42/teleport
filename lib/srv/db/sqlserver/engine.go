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

package sqlserver

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/common/role"
	"github.com/gravitational/teleport/lib/srv/db/sqlserver/protocol"

	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/denisenkom/go-mssqldb/msdsn"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

//
type Engine struct {
	// Auth handles database access authentication.
	Auth common.Auth
	// Audit emits database access audit events.
	Audit common.Audit
	// Context is the database server close context.
	Context context.Context
	// Clock is the clock interface.
	Clock clockwork.Clock
	// Log is used for logging.
	Log logrus.FieldLogger
	//
	clientConn net.Conn
}

// InitializeConnection initializes the client connection.
func (e *Engine) InitializeConnection(clientConn net.Conn, _ *common.Session) error {
	e.clientConn = clientConn
	return nil
}

// SendError sends an error to SQL Server client.
func (e *Engine) SendError(err error) {
}

func (e *Engine) handleLogin7(sessionCtx *common.Session) (*protocol.Login7Packet, error) {
	pkt, err := protocol.ReadLogin7Packet(e.clientConn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	e.Log.Debugf("Got LOGIN7 packet: %#v.", pkt)

	// err = protocol.WriteLogin7Response(e.clientConn, pkt.Database)
	// if err != nil {
	// 	return nil, trace.Wrap(err)
	// }

	sessionCtx.DatabaseUser = pkt.User
	if pkt.Database != "" {
		sessionCtx.DatabaseName = pkt.Database
	}

	e.Log.Debugf("LOGIN7 DONE ====")
	return pkt, nil
}

//
func (e *Engine) HandleConnection(ctx context.Context, sessionCtx *common.Session) error {
	fmt.Println("=== [AGENT] Received SQL Server connection ===")

	login7, err := e.handleLogin7(sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}

	err = e.checkAccess(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}

	host, port, err := net.SplitHostPort(sessionCtx.Database.GetURI())
	if err != nil {
		return trace.Wrap(err)
	}

	portI, err := strconv.ParseUint(port, 10, 64)
	if err != nil {
		return trace.Wrap(err)
	}

	// auth, err := e.getAuth(sessionCtx)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }

	// connector := mssql.NewConnectorConfig(msdsn.Config{
	// 	Host:       host,
	// 	Port:       portI,
	// 	Encryption: msdsn.EncryptionRequired,
	// 	TLSConfig:  &tls.Config{InsecureSkipVerify: true},
	// }, auth)

	connector := mssql.NewConnectorConfig(msdsn.Config{
		Host:         host,
		Port:         portI,
		User:         sessionCtx.DatabaseUser,
		Password:     os.Getenv("SQL_SERVER_PASS"),
		Database:     sessionCtx.DatabaseName,
		Encryption:   msdsn.EncryptionRequired,
		TLSConfig:    &tls.Config{InsecureSkipVerify: true},
		OptionFlags1: login7.Fields.OptionFlags1,
		OptionFlags2: login7.Fields.OptionFlags2,
		TypeFlags:    login7.Fields.TypeFlags,
		OptionFlags3: login7.Fields.OptionFlags3,
	}, nil)

	conn, err := connector.Connect(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer conn.Close()

	mssqlConn, ok := conn.(*mssql.Conn)
	if !ok {
		return trace.BadParameter("expected *mssql.Conn, got: %T", conn)
	}

	tokens, err := mssqlConn.GetLoginTokens()
	if err != nil {
		return trace.Wrap(err)
	}

	err = protocol.WriteLogin7Response(e.clientConn, tokens)
	if err != nil {
		return trace.Wrap(err)
	}

	serverConn := mssqlConn.GetUnderlyingConn()

	fmt.Println("Connected to SQL server", host, serverConn)

	// Copy between the connections.
	clientErrCh := make(chan error, 1)
	serverErrCh := make(chan error, 1)

	go e.receiveFromClient(e.clientConn, serverConn, clientErrCh)
	go e.receiveFromServer(serverConn, e.clientConn, serverErrCh)

	select {
	case err := <-clientErrCh:
		e.Log.WithError(err).Debug("Client done.")
	case err := <-serverErrCh:
		e.Log.WithError(err).Debug("Server done.")
	case <-ctx.Done():
		e.Log.Debug("Context canceled.")
	}

	return nil
}

func (e *Engine) checkAccess(ctx context.Context, sessionCtx *common.Session) error {
	ap, err := e.Auth.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	mfaParams := services.AccessMFAParams{
		Verified:       sessionCtx.Identity.MFAVerified != "",
		AlwaysRequired: ap.GetRequireSessionMFA(),
	}
	// TODO(r0mant): Check database name matcher.
	dbRoleMatchers := role.DatabaseRoleMatchers(
		sessionCtx.Database.GetProtocol(),
		sessionCtx.DatabaseUser,
		sessionCtx.DatabaseName,
	)
	err = sessionCtx.Checker.CheckAccess(
		sessionCtx.Database,
		mfaParams,
		dbRoleMatchers...,
	)
	if err != nil {
		e.Audit.OnSessionStart(e.Context, sessionCtx, err)
		return trace.Wrap(err)
	}
	return nil
}

func (e *Engine) receiveFromClient(clientConn, serverConn io.ReadWriteCloser, clientErrCh chan<- error) {
	log := e.Log.WithFields(logrus.Fields{
		"from": "client",
	})
	defer func() {
		log.Debug("Stop receiving from client.")
		close(clientErrCh)
	}()
	for {
		pkt, err := protocol.ReadPacket(clientConn)
		if err != nil {
			log.WithError(err).Error("Failed to read from client.")
			clientErrCh <- err
			return
		}

		buf := append(pkt.HeaderBytes, pkt.Data...)

		// if pkt.Type == protocol.PacketTypeSQLBatch {
		// 	sqlBatch, err := protocol.ParseSQLBatchPacket(pkt)
		// 	if err != nil {
		// 		log.WithError(err).Error("Failed to parse SQLBatch packet.")
		// 	} else {
		// 		log.Debugf("===> Got query: %v", sqlBatch.Query)
		// 	}
		// }

		// buf := make([]byte, 4096)

		// n, err := clientConn.Read(buf)
		// if err != nil {
		// 	log.WithError(err).Error("Failed to read from client.")
		// 	clientErrCh <- err
		// 	return
		// }

		fmt.Printf("================> (len: %v)\n", len(buf))
		fmt.Println(hex.Dump(buf))

		_, err = serverConn.Write(buf)
		if err != nil {
			log.WithError(err).Error("Failed to write to server.")
			clientErrCh <- err
			return
		}
	}
}

func (e *Engine) receiveFromServer(serverConn, clientConn io.ReadWriteCloser, serverErrCh chan<- error) {
	log := e.Log.WithFields(logrus.Fields{
		"from": "server",
	})
	defer func() {
		log.Debug("Stop receiving from server.")
		close(serverErrCh)
	}()
	for {
		buf := make([]byte, 4096)

		n, err := serverConn.Read(buf)
		if err != nil {
			log.WithError(err).Error("Failed to read from server.")
			serverErrCh <- err
			return
		}

		fmt.Printf("<================ (len: %v)\n", n)
		fmt.Println(hex.Dump(buf[:n]))

		_, err = clientConn.Write(buf[:n])
		if err != nil {
			log.WithError(err).Error("Failed to write to client.")
			serverErrCh <- err
			return
		}
	}
}
