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

package routerclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func certificates(t *testing.T) ([]byte, tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	issue := func(serial int64, server bool) ([]byte, tls.Certificate) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"atenet-router.ate-system.svc"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		private, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})...)
		cert, e := tls.X509KeyPair(bundle, bundle)
		if e != nil {
			t.Fatal(e)
		}
		return bundle, cert
	}
	_, server := issue(2, true)
	client, _ := issue(3, false)
	return caPEM, server, client
}

func TestHTTPMutualTLSAndRotation(t *testing.T) {
	// A router connection must not inherit a proxy that can bypass DialTLSContext.
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.Proxy = func(*http.Request) (*url.URL, error) { return nil, errors.New("unexpected HTTP proxy") }
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	ca, serverCert, clientCert := certificates(t)
	pools := x509.NewCertPool()
	pools.AppendCertsFromPEM(ca)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("unverified client")
		}
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pools, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "credential.pem")
	os.WriteFile(caPath, ca, 0600)
	os.WriteFile(certPath, clientCert, 0600)
	cfg := Config{CAFile: caPath, CredentialFile: certPath, ServerName: "atenet-router.ate-system.svc"}
	client, err := cfg.HTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.Status)
	}
	for _, field := range []string{"roots", "client", "name"} {
		t.Run(field, func(t *testing.T) {
			client.CloseIdleConnections()
			switch field {
			case "roots":
				os.WriteFile(caPath, []byte("invalid"), 0600)
			case "client":
				os.WriteFile(certPath, []byte("invalid"), 0600)
			case "name":
				cfg.ServerName = "wrong.example"
			}
			bad, err := cfg.HTTPClient()
			if err == nil {
				defer bad.CloseIdleConnections()
				r, e := bad.Get(server.URL)
				if r != nil {
					r.Body.Close()
				}
				if e == nil {
					t.Fatal("invalid credentials accepted")
				}
			}
			os.WriteFile(caPath, ca, 0600)
			os.WriteFile(certPath, clientCert, 0600)
			cfg.ServerName = "atenet-router.ate-system.svc"
		})
	}
	// An already created client must reload projected files for a new connection.
	client.CloseIdleConnections()
	os.WriteFile(caPath, []byte("broken rotation"), 0600)
	if r, e := client.Get(server.URL); e == nil {
		r.Body.Close()
		t.Fatal("stale roots retained after invalid rotation")
	}
	os.WriteFile(caPath, ca, 0600)
	r, e := client.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
}

func TestConfigurationRejectsPartialTLS(t *testing.T) {
	for _, cfg := range []Config{{CAFile: "ca"}, {CredentialFile: "cert"}} {
		if _, err := cfg.TLSConfig(); err == nil {
			t.Fatal("partial TLS accepted")
		}
	}
}

func TestGRPCCredentialsUseVerifiedTLS(t *testing.T) {
	ca, serverCert, clientCert := certificates(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca"), ca, 0600)
	os.WriteFile(filepath.Join(dir, "cert"), clientCert, 0600)
	cfg := Config{CAFile: filepath.Join(dir, "ca"), CredentialFile: filepath.Join(dir, "cert"), ServerName: "atenet-router.ate-system.svc"}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			defer conn.Close()
			e = conn.(*tls.Conn).Handshake()
		}
		done <- e
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := cfg.GRPCCredentials()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := credentials.ClientHandshake(ctx, "127.0.0.1", raw)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
