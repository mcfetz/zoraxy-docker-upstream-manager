package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
	Client for the Zoraxy plugin REST API.

	The plugin is granted an API key (ConfigureSpec.APIKey) scoped to the
	endpoints declared in the introspect spec (PermittedAPIEndpoints). All
	calls go to http://localhost:{ZoraxyPort}/plugin/api/... with a
	"Authorization: Bearer <key>" header.
*/

type ZoraxyAPI struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewZoraxyAPI(zoraxyPort int, apiKey string) *ZoraxyAPI {
	return &ZoraxyAPI{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d/plugin", zoraxyPort),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type ProxyEndpointInfo struct {
	RootOrMatchingDomain string   `json:"RootOrMatchingDomain"`
	MatchingDomainAlias  []string `json:"MatchingDomainAlias"`
	Disabled             bool     `json:"Disabled"`
}

// ListEndpoints returns all "host" type proxy rules (the `ep` key used by the
// upstream management endpoints is RootOrMatchingDomain).
func (z *ZoraxyAPI) ListEndpoints() ([]ProxyEndpointInfo, error) {
	req, err := z.request(http.MethodGet, "/api/proxy/list?type=host", nil)
	if err != nil {
		return nil, err
	}
	resp, err := z.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list endpoints (HTTP %d): %s", resp.StatusCode, sanitizeError(body))
	}

	// A {"error": "..."} JSON is returned on failure
	if strings.Contains(string(body), `"error"`) {
		var errMsg struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errMsg) == nil && errMsg.Error != "" {
			return nil, fmt.Errorf("%s", errMsg.Error)
		}
	}

	endpoints := []ProxyEndpointInfo{}
	if err := json.Unmarshal(body, &endpoints); err != nil {
		return nil, fmt.Errorf("unexpected proxy/list response: %w", err)
	}
	return endpoints, nil
}

// normalizeOrigin strips an optional scheme and path from an origin address so
// it can be compared to a candidate address.
func normalizeOrigin(o string) string {
	o = strings.TrimSpace(o)
	if i := strings.Index(o, "://"); i >= 0 {
		o = o[i+3:]
	}
	if i := strings.Index(o, "/"); i >= 0 {
		o = o[:i]
	}
	return strings.ToLower(o)
}

// ProxyUpstreamInfo mirrors the OriginIpOrDomain field of a proxy upstream.
type ProxyUpstreamInfo struct {
	OriginIpOrDomain string `json:"OriginIpOrDomain"`
}

// UpstreamOriginInfo augments an upstream origin with its active state.
type UpstreamOriginInfo struct {
	ProxyUpstreamInfo
	Active bool `json:"active"`
}

// LinkedRule describes one proxy rule that uses a given upstream port.
type LinkedRule struct {
	Domain string `json:"domain"`
	Origin string `json:"origin"`
}

type proxyUpstreamList struct {
	ActiveOrigins   []ProxyUpstreamInfo `json:"ActiveOrigins"`
	InactiveOrigins []ProxyUpstreamInfo `json:"InactiveOrigins"`
}

// originPort extracts the port from an upstream origin ("host:port"). Origins
// without a numeric port yield 0.
func originPort(origin string) uint16 {
	o := normalizeOrigin(origin)
	if o == "" {
		return 0
	}
	if _, p, err := net.SplitHostPort(o); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			return uint16(n)
		}
	}
	if i := strings.LastIndex(o, ":"); i > 0 {
		if n, err := strconv.Atoi(o[i+1:]); err == nil && n > 0 && n < 65536 {
			return uint16(n)
		}
	}
	return 0
}

// originHost extracts the lower-cased host part of an upstream origin, or
// "" when it cannot be determined.
func originHost(origin string) string {
	o := normalizeOrigin(origin)
	if i := strings.LastIndex(o, ":"); i > 0 {
		o = o[:i]
	}
	return o
}

// addRule appends a rule unless the same (domain, origin) pair is already there.
func addRule(m map[uint16][]LinkedRule, port uint16, r LinkedRule) {
	if port == 0 {
		return
	}
	for _, existing := range m[port] {
		if existing.Domain == r.Domain && existing.Origin == r.Origin {
			return
		}
	}
	m[port] = append(m[port], r)
}

// ListLinkedOrigins maps every upstream port ("host:port") that is already
// attached to a proxy rule to the rules using it. Matching is port-based: a
// swarm published port is reachable on every swarm node, so the rule origin may
// reference a different node than the one the candidate was scanned on. The
// upstream list is fetched per endpoint in parallel.
func (z *ZoraxyAPI) ListLinkedOrigins() (map[uint16][]LinkedRule, error) {
	endpoints, err := z.ListEndpoints()
	if err != nil {
		return nil, err
	}
	linked := map[uint16][]LinkedRule{}
	if len(endpoints) == 0 {
		return linked, nil
	}

	const max = 8
	sem := make(chan struct{}, max)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		wg.Add(1)
		go func(ep ProxyEndpointInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := z.request(http.MethodGet,
				"/api/proxy/upstream/list?ep="+url.QueryEscape(ep.RootOrMatchingDomain), nil)
			if err != nil {
				return
			}
			resp, err := z.httpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}
			var list proxyUpstreamList
			if json.Unmarshal(body, &list) != nil {
				return
			}
			mu.Lock()
			for _, u := range append(list.ActiveOrigins, list.InactiveOrigins...) {
				addRule(linked, originPort(u.OriginIpOrDomain), LinkedRule{
					Domain: ep.RootOrMatchingDomain,
					Origin: strings.TrimSpace(u.OriginIpOrDomain),
				})
			}
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
	return linked, nil
}

// AddUpstream registers a new upstream origin on the given proxy endpoint.
func (z *ZoraxyAPI) AddUpstream(ep, origin string) error {
	form := url.Values{}
	form.Set("ep", ep)
	form.Set("origin", origin)
	form.Set("tls", "false")
	form.Set("tlsval", "false")
	form.Set("bpwsorg", "true")
	form.Set("active", "true")
	form.Set("maxconn", "0")
	form.Set("respt", "0")

	req, err := z.request(http.MethodPost, "/api/proxy/upstream/add", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("add upstream (HTTP %d): %s", resp.StatusCode, sanitizeError(body))
	}
	if strings.Contains(string(body), `"error"`) {
		var errMsg struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errMsg) == nil && errMsg.Error != "" {
			return fmt.Errorf("%s", errMsg.Error)
		}
	}
	return nil
}

// ListUpstreams returns all upstream origins (active and inactive) registered
// on the given proxy endpoint rule.
func (z *ZoraxyAPI) ListUpstreams(ep string) ([]UpstreamOriginInfo, error) {
	req, err := z.request(http.MethodGet,
		"/api/proxy/upstream/list?ep="+url.QueryEscape(ep), nil)
	if err != nil {
		return nil, err
	}
	resp, err := z.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list upstreams (HTTP %d): %s", resp.StatusCode, sanitizeError(body))
	}
	var list struct {
		ActiveOrigins   []ProxyUpstreamInfo `json:"ActiveOrigins"`
		InactiveOrigins []ProxyUpstreamInfo `json:"InactiveOrigins"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("unexpected upstream/list response: %w", err)
	}
	out := make([]UpstreamOriginInfo, 0, len(list.ActiveOrigins)+len(list.InactiveOrigins))
	for _, u := range list.ActiveOrigins {
		out = append(out, UpstreamOriginInfo{ProxyUpstreamInfo: u, Active: true})
	}
	for _, u := range list.InactiveOrigins {
		out = append(out, UpstreamOriginInfo{ProxyUpstreamInfo: u, Active: false})
	}
	return out, nil
}

// UpdateUpstream re-registers an origin under a new address. Every field not
// present in the payload keeps its previous value, so a bulk host switch only
// needs to change OriginIpOrDomain.
func (z *ZoraxyAPI) UpdateUpstream(ep, oldOrigin, newOrigin string, active bool) error {
	payload := fmt.Sprintf(`{"OriginIpOrDomain":%s}`, jsonStr(newOrigin))
	form := url.Values{}
	form.Set("ep", ep)
	form.Set("origin", oldOrigin)
	form.Set("payload", payload)
	form.Set("active", strconv.FormatBool(active))
	return z.postForm("/api/proxy/upstream/update", form, "update upstream")
}

// RemoveUpstream removes an upstream origin from the given proxy endpoint rule.
func (z *ZoraxyAPI) RemoveUpstream(ep, origin string) error {
	form := url.Values{}
	form.Set("ep", ep)
	form.Set("origin", origin)
	return z.postForm("/api/proxy/upstream/remove", form, "remove upstream")
}

func (z *ZoraxyAPI) postForm(path string, form url.Values, label string) error {
	req, err := z.request(http.MethodPost, path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s (HTTP %d): %s", label, resp.StatusCode, sanitizeError(body))
	}
	if strings.Contains(string(body), `"error"`) {
		var errMsg struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errMsg) == nil && errMsg.Error != "" {
			return fmt.Errorf("%s", errMsg.Error)
		}
	}
	return nil
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (z *ZoraxyAPI) request(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, z.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+z.apiKey)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func sanitizeError(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
