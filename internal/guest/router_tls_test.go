// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package guest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-substrate/env/guest/process"
	ateenv "github.com/agent-substrate/env/proto/ateenv/v1alpha"
	"github.com/google/ax/internal/guest"
	"github.com/google/ax/internal/routerclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type routerIdentity struct {
	roots, bundle []byte
	server        tls.Certificate
	clientDER     []byte
}

// The second identity shares the CA; the third rotates the CA and server too.
func routerIdentities(t *testing.T) []routerIdentity {
	t.Helper()
	makePair := func(base int64) []routerIdentity {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{SerialNumber: big.NewInt(base), Subject: pkix.Name{CommonName: fmt.Sprint(base)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		issue := func(serial int64, usage x509.ExtKeyUsage) ([]byte, tls.Certificate) {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"atenet-router.ate-system.svc"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
			raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, &k.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			private, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				t.Fatal(err)
			}
			bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})...)
			cert, err := tls.X509KeyPair(bundle, bundle)
			if err != nil {
				t.Fatal(err)
			}
			return bundle, cert
		}
		_, server := issue(base+1, x509.ExtKeyUsageServerAuth)
		var pair []routerIdentity
		for _, serial := range []int64{base + 2, base + 3} {
			bundle, cert := issue(serial, x509.ExtKeyUsageClientAuth)
			pair = append(pair, routerIdentity{roots, bundle, server, cert.Certificate[0]})
		}
		return pair
	}
	return append(makePair(10), makePair(20)[0])
}

func (id routerIdentity) serverTLS() *tls.Config {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(id.roots)
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{id.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"h2", "http/1.1"}}
}

// Keep stable symlink paths while atomically replacing the projected generation.
func projectRouterIdentity(t *testing.T, dir string, generation int, id routerIdentity) {
	t.Helper()
	name := fmt.Sprintf("generation-%d", generation)
	folder := filepath.Join(dir, name)
	if err := os.Mkdir(folder, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"ca.pem": id.roots, "client.pem": id.bundle} {
		if err := os.WriteFile(filepath.Join(folder, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	pending := filepath.Join(dir, "pending")
	if err := os.Symlink(name, pending); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pending, filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
}

func routerConfig(dir string) routerclient.Config {
	return routerclient.Config{CAFile: filepath.Join(dir, "current", "ca.pem"), CredentialFile: filepath.Join(dir, "current", "client.pem"), ServerName: "atenet-router.ate-system.svc"}
}

// Catches clients that cache the first certificate or trust roots, or resolve
// the projected symlink once rather than reopening it on each handshake.
func TestRouterHTTPAdoptsRotatedIdentity(t *testing.T) {
	identities := routerIdentities(t)
	dir := t.TempDir()
	projectRouterIdentity(t, dir, 0, identities[0])
	var current atomic.Pointer[routerIdentity]
	current.Store(&identities[0])
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := current.Load()
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, id.clientDER) {
			http.Error(w, "stale client identity", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return current.Load().serverTLS(), nil }}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := routerConfig(dir).HTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	for i := range identities {
		if i > 0 {
			projectRouterIdentity(t, dir, i, identities[i])
			current.Store(&identities[i])
			client.CloseIdleConnections()
		}
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("generation %d request: %v", i, err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("generation %d: server rejected client identity: %s", i, response.Status)
		}
	}
}

type reconnectListener struct {
	net.Listener
	mu          sync.Mutex
	connections []net.Conn
}

func (l *reconnectListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.connections = append(l.connections, c)
		l.mu.Unlock()
	}
	return c, err
}
func (l *reconnectListener) disconnect() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.connections {
		c.Close()
	}
	l.connections = nil
}

// Exercises AX's real guest client and the real process service, including
// unary and streaming actor metadata. The SAME client must reconnect with the
// new identity; creating a fresh client after rotation would miss stale state.
func TestDialTargetRoutesExecAfterCertificateRotation(t *testing.T) {
	identities := routerIdentities(t)
	dir := t.TempDir()
	projectRouterIdentity(t, dir, 0, identities[0])
	var current atomic.Pointer[routerIdentity]
	current.Store(&identities[0])
	var unary, stream atomic.Int64
	authorize := func(ctx context.Context) error {
		md, _ := metadata.FromIncomingContext(ctx)
		targets := md.Get("ate-target-actor")
		if len(targets) != 1 || targets[0] != "scope/task" {
			return status.Error(codes.PermissionDenied, "missing actor routing metadata")
		}
		p, ok := peer.FromContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "missing TLS peer")
		}
		auth, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(auth.State.VerifiedChains) == 0 || !bytes.Equal(auth.State.PeerCertificates[0].Raw, current.Load().clientDER) {
			return status.Error(codes.Unauthenticated, "stale client identity")
		}
		return nil
	}
	cfg := &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return current.Load().serverTLS(), nil }}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			if err := authorize(ctx); err != nil {
				return nil, err
			}
			unary.Add(1)
			return next(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			if err := authorize(ss.Context()); err != nil {
				return err
			}
			stream.Add(1)
			return next(srv, ss)
		}))
	trackerCfg := process.DefaultConfig(t.TempDir())
	trackerCfg.Workspace = t.TempDir()
	tracker, err := process.NewTracker(trackerCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tracker.Close() })
	ateenv.RegisterProcessServiceServer(server, process.NewService(tracker))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tracked := &reconnectListener{Listener: listener}
	go func() { _ = server.Serve(tracked) }()
	t.Cleanup(server.Stop)
	client, err := guest.DialTarget(listener.Addr().String(), "scope/task", routerConfig(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	for i := range identities {
		if i > 0 {
			projectRouterIdentity(t, dir, i, identities[i])
			current.Store(&identities[i])
			tracked.disconnect()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		want := fmt.Sprintf("generation-%d", i)
		for {
			var output bytes.Buffer
			code, err := client.Exec(ctx, guest.ExecOptions{Command: []string{"printf", want}, Stdout: &output})
			if err == nil {
				if code != 0 || output.String() != want {
					t.Fatalf("generation %d: code=%d output=%q", i, code, output.String())
				}
				break
			}
			// Closing the transport can race the next RPC. Only retry Unavailable,
			// never auth/metadata failures; this fixture command has no side effects.
			if status.Code(err) != codes.Unavailable || ctx.Err() != nil {
				cancel()
				t.Fatalf("generation %d Exec: %v", i, err)
			}
			select {
			case <-ctx.Done():
				cancel()
				t.Fatalf("generation %d reconnect timed out: %v", i, err)
			case <-time.After(20 * time.Millisecond):
			}
		}
		cancel()
	}
	if unary.Load() < 3 || stream.Load() < 3 {
		t.Fatalf("real RPCs missing: unary=%d stream=%d", unary.Load(), stream.Load())
	}
}
