package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

func newHostID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const (
	configFileName = "config.json"
)

// DockerHost describes a Docker daemon the plugin can query.
// The Endpoint field accepts the following formats:
//
//	unix:///var/run/docker.sock  (local socket)
//	tcp://192.168.1.10:2375      (plain TCP, Docker Engine API)
//	tcps://192.168.1.10:2376     (TLS encrypted TCP, Docker Engine API)
//	http://192.168.1.10:2375     (plain HTTP)
//	https://192.168.1.10:2376    (TLS HTTP)
//
// A bare "host:port" value is treated as tcp:// and uses plain HTTP unless
// TLS is enabled.
type DockerHost struct {
	ID              string `json:"id"`
	Name            string `json:"name,omitempty"`
	Endpoint        string `json:"endpoint"`
	TLS             bool   `json:"tls,omitempty"`
	InsecureSkipTLS bool   `json:"insecure_skip_tls,omitempty"`
	CACertPath      string `json:"ca_cert_path,omitempty"`
	ClientCertPath  string `json:"client_cert_path,omitempty"`
	ClientKeyPath   string `json:"client_key_path,omitempty"`

	// SuggestIP overrides the IP address that is recommended for new
	// upstream origins targeting this host. Leave empty to derive the
	// address from the endpoint (e.g. the host part of a tcp:// URL).
	SuggestIP string `json:"suggest_ip,omitempty"`
}

type appConfig struct {
	DockerHosts []DockerHost `json:"docker_hosts"`

	// PollingIntervalSeconds is the minimal interval the frontend uses when
	// auto-refreshing the container list.
	PollingIntervalSeconds int `json:"polling_interval_seconds"`
}

type configStore struct {
	mu   sync.RWMutex
	path string
	cfg  *appConfig
}

func newConfigStore(path string) (*configStore, error) {
	s := &configStore{
		path: path,
		cfg:  &appConfig{PollingIntervalSeconds: 10},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	if len(s.cfg.DockerHosts) == 0 {
		s.cfg.DockerHosts = []DockerHost{}
	}
	return s, nil
}

func (s *configStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var cfg appConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if cfg.DockerHosts == nil {
		cfg.DockerHosts = []DockerHost{}
	}
	s.cfg = &cfg
	return nil
}

// save persists the config. Callers must already hold the lock (s.mu).
func (s *configStore) save() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0644)
}

func (s *configStore) hosts() []DockerHost {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DockerHost, len(s.cfg.DockerHosts))
	copy(out, s.cfg.DockerHosts)
	return out
}

func (s *configStore) upsertHost(h DockerHost) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.cfg.DockerHosts {
		if existing.ID == h.ID {
			s.cfg.DockerHosts[i] = h
			return s.save()
		}
	}
	if h.ID == "" {
		h.ID = newHostID()
	}
	s.cfg.DockerHosts = append(s.cfg.DockerHosts, h)
	return s.save()
}

func (s *configStore) removeHost(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.cfg.DockerHosts {
		if existing.ID == id {
			s.cfg.DockerHosts = append(s.cfg.DockerHosts[:i], s.cfg.DockerHosts[i+1:]...)
			return s.save()
		}
	}
	return nil
}

func (s *configStore) pollingInterval() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.PollingIntervalSeconds <= 0 {
		return 10
	}
	return s.cfg.PollingIntervalSeconds
}

func (s *configStore) setPollingInterval(seconds int) error {
	if seconds <= 0 {
		seconds = 10
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.PollingIntervalSeconds = seconds
	return s.save()
}
