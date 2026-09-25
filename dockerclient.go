package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

/*
	Minimal Docker Engine API client.

	Only the endpoints required by this plugin are implemented:
	  GET  /version           -> API version negotiation
	  GET  /containers/json   -> list containers with published ports
*/

const dialTimeout = 5 * time.Second

type APIPort struct {
	IP          string `json:"IP"`
	PrivatePort uint16 `json:"PrivatePort"`
	PublicPort  uint16 `json:"PublicPort"`
	Type        string `json:"Type"`
}

type APIContainer struct {
	ID         string            `json:"Id"`
	Names      []string          `json:"Names"`
	Image      string            `json:"Image"`
	State      string            `json:"State"`
	Status     string            `json:"Status"`
	Ports      []APIPort         `json:"Ports"`
	Labels     map[string]string `json:"Labels"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type endpoint struct {
	scheme   string // "unix", "http", "https"
	address  string // unix socket path, or "host:port" for http(s)
	hostPort string // host:port for http(s), empty for unix
}

// parseEndpoint normalises the supported endpoint strings from a DockerHost.
func parseEndpoint(h DockerHost) (endpoint, error) {
	ep := h.Endpoint
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return endpoint{}, fmt.Errorf("empty docker endpoint")
	}

	// Bare host:port
	if !strings.Contains(ep, "://") {
		scheme := "http"
		if h.TLS {
			scheme = "https"
		}
		return endpoint{scheme: scheme, address: ep, hostPort: ep}, nil
	}

	u, err := url.Parse(ep)
	if err != nil {
		return endpoint{}, fmt.Errorf("invalid docker endpoint %q: %w", ep, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "unix":
		if strings.HasPrefix(u.Path, "//") {
			u.Path = strings.TrimPrefix(u.Path, "//")
		}
		return endpoint{scheme: "unix", address: u.Path}, nil
	case "tcp", "http":
		addr := u.Host
		if addr == "" {
			addr = u.Path
		}
		return endpoint{scheme: "http", address: addr, hostPort: addr}, nil
	case "tcps", "tcp+ssl", "https":
		addr := u.Host
		if addr == "" {
			addr = u.Path
		}
		return endpoint{scheme: "https", address: addr, hostPort: addr}, nil
	default:
		return endpoint{}, fmt.Errorf("unsupported docker endpoint scheme %q", u.Scheme)
	}
}

func (e endpoint) baseURL() string {
	if e.scheme == "unix" {
		return "http://docker"
	}
	return e.scheme + "://" + e.hostPort
}

func (h DockerHost) newHTTPClient() (*http.Client, error) {
	ep, err := parseEndpoint(h)
	if err != nil {
		return nil, err
	}

	var dialer *net.Dialer
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dialer == nil {
				dialer = &net.Dialer{Timeout: dialTimeout}
			}
			if ep.scheme == "unix" {
				return dialer.DialContext(ctx, "unix", ep.address)
			}
			return dialer.DialContext(ctx, "tcp", ep.hostPort)
		},
	}

	if ep.scheme == "https" {
		tlsConfig, err := buildTLSConfig(h)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}, nil
}

func buildTLSConfig(h DockerHost) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: h.InsecureSkipTLS, //nolint:gosec // user opt-in for self-signed daemons
	}

	// Load a client certificate if all pieces are provided.
	if h.ClientCertPath != "" && h.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(h.ClientCertPath, h.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load docker client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load a custom CA bundle if provided.
	if h.CACertPath != "" {
		caPEM, err := os.ReadFile(h.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read docker CA bundle: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse docker CA bundle")
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// apiPrefix returns the negotiated API version prefix (e.g. "/v1.44").
// Negotiating prevents "client version X is too new" errors on older daemons.
func apiPrefix(client *http.Client, base string) string {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/version", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var v struct {
		APIVersion string `json:"ApiVersion"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil || v.APIVersion == "" {
		return ""
	}
	return "/v" + v.APIVersion
}

// Ping returns the daemon version string or an error if the host is unreachable.
func (h DockerHost) Ping() (string, error) {
	client, err := h.newHTTPClient()
	if err != nil {
		return "", err
	}
	ep, _ := parseEndpoint(h)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.baseURL()+"/version", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("docker endpoint returned status %d", resp.StatusCode)
	}
	var v struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	if v.Version == "" {
		return "unknown", nil
	}
	return v.Version, nil
}

// ListContainers returns all containers on the host (running and stopped).
func (h DockerHost) ListContainers() ([]APIContainer, error) {
	client, err := h.newHTTPClient()
	if err != nil {
		return nil, err
	}
	ep, _ := parseEndpoint(h)
	prefix := apiPrefix(client, ep.baseURL())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		ep.baseURL()+prefix+"/containers/json?all=1", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Message != "" {
			return nil, fmt.Errorf("%s", errBody.Message)
		}
		return nil, fmt.Errorf("docker endpoint returned status %d", resp.StatusCode)
	}

	containers := []APIContainer{}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, err
	}
	return containers, nil
}

// ServicePort describes a port published by a swarm service.
type ServicePort struct {
	Protocol      string `json:"Protocol"`
	TargetPort    uint16 `json:"TargetPort"`
	PublishedPort uint16 `json:"PublishedPort"`
	PublishMode   string `json:"PublishMode"`
}

// APIService is a minimal swarm service representation.
type APIService struct {
	Spec struct {
		Name string `json:"Name"`
	} `json:"Spec"`
	Endpoint struct {
		Ports []ServicePort `json:"Ports"`
	} `json:"Endpoint"`
}

// ListServices returns the swarm services of the host, or nil when the daemon
// is not part of a swarm. The daemon reports published ports of swarm services
// only here - task containers do not carry them in /containers/json.
func (h DockerHost) ListServices() ([]APIService, error) {
	client, err := h.newHTTPClient()
	if err != nil {
		return nil, err
	}
	ep, _ := parseEndpoint(h)
	prefix := apiPrefix(client, ep.baseURL())
	base := ep.baseURL()

	// Probe swarm mode first: /swarm returns 200 only on swarm managers.
	swarmCtx, swarmCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer swarmCancel()
	req, err := http.NewRequestWithContext(swarmCtx,
		http.MethodGet, base+prefix+"/swarm", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil // not reachable / not swarm -> behave as plain docker
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	svcCtx, svcCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer svcCancel()
	req, err = http.NewRequestWithContext(svcCtx,
		http.MethodGet, base+prefix+"/services", nil)
	if err != nil {
		return nil, err
	}
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Message != "" {
			return nil, fmt.Errorf("%s", errBody.Message)
		}
		return nil, fmt.Errorf("docker endpoint returned status %d", resp.StatusCode)
	}

	services := []APIService{}
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return nil, err
	}
	return services, nil
}

// suggestedAddress derives the recommended upstream IP for this host.
func (h DockerHost) suggestedAddress() string {
	if h.SuggestIP != "" {
		return h.SuggestIP
	}
	ep, err := parseEndpoint(h)
	if err != nil {
		return ""
	}
	if ep.scheme == "unix" {
		return ""
	}
	host, _, err := net.SplitHostPort(ep.hostPort)
	if err != nil {
		// Endpoint without explicit port, use it as-is
		return ep.hostPort
	}
	return host
}
