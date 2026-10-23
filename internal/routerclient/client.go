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

// Package routerclient configures authenticated connections to atenet-router.
package routerclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config names the projected trust and credential bundles, which are reloaded
// for each handshake. CredentialFile contains the certificate and private key.
type Config struct {
	Address        string
	CAFile         string
	CredentialFile string
	ServerName     string
}

func FromEnv() Config {
	return Config{Address: os.Getenv("ATENET_ROUTER_ADDR"), CAFile: os.Getenv("ATENET_ROUTER_CA_FILE"), CredentialFile: os.Getenv("ATENET_ROUTER_CLIENT_CERT"), ServerName: os.Getenv("ATENET_ROUTER_SERVER_NAME")}
}

func (c Config) TLS() bool { return c.CAFile != "" || c.CredentialFile != "" || c.ServerName != "" }

func (c Config) name() string {
	if c.ServerName != "" {
		return c.ServerName
	}
	return "atenet-router.ate-system.svc"
}

// URL accepts the previous host:port setting and an explicit HTTP(S) URL.
func (c Config) URL() (string, error) {
	address := c.Address
	if address == "" {
		return "", nil
	}
	if !strings.Contains(address, "://") {
		if c.TLS() {
			address = "https://" + address
		} else {
			address = "http://" + address
		}
	}
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("invalid router address")
	}
	if (c.TLS() && u.Scheme != "https") || (!c.TLS() && u.Scheme != "http") {
		return "", fmt.Errorf("router scheme and TLS credentials disagree")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func (c Config) TLSConfig() (*tls.Config, error) {
	if !c.TLS() {
		return nil, nil
	}
	if c.CAFile == "" || c.CredentialFile == "" {
		return nil, fmt.Errorf("router TLS requires both a CA file and a client credential bundle")
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("reading router CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("router CA file contains no certificates")
	}
	bundle, err := os.ReadFile(c.CredentialFile)
	if err != nil {
		return nil, fmt.Errorf("reading router client credential: %w", err)
	}
	cert, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return nil, fmt.Errorf("loading router client credential: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: c.name()}, nil
}

func (c Config) HTTPClient() (*http.Client, error) {
	if _, err := c.TLSConfig(); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The router is a cluster service (or a localhost forward). A CONNECT proxy
	// would bypass DialTLSContext and its projected credentials.
	transport.Proxy = nil
	if c.TLS() {
		transport.ForceAttemptHTTP2 = true
		transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			cfg, err := c.TLSConfig()
			if err != nil {
				return nil, err
			}
			cfg.NextProtos = []string{"h2", "http/1.1"}
			return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, address)
		}
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (c Config) GRPCCredentials() (credentials.TransportCredentials, error) {
	if _, err := c.TLSConfig(); err != nil {
		return nil, err
	}
	if !c.TLS() {
		return insecure.NewCredentials(), nil
	}
	return &fileCredentials{config: c}, nil
}

type fileCredentials struct{ config Config }

func (c *fileCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cfg, err := c.config.TLSConfig()
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	// grpc-go derives the TLS name from this argument, even when Config sets it.
	return credentials.NewTLS(cfg).ClientHandshake(ctx, c.config.name(), raw)
}
func (c *fileCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("router credentials are client-only")
}
func (c *fileCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.config.name()}).Info()
}
func (c *fileCredentials) Clone() credentials.TransportCredentials {
	return &fileCredentials{config: c.config}
}
func (c *fileCredentials) OverrideServerName(name string) error {
	c.config.ServerName = name
	return nil
}
