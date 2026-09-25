package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

/*
	Internal REST API of the plugin, served under the UI path prefix.
	The frontend reaches these endpoints through Zoraxy's plugin UI reverse
	proxy, e.g. /plugin.ui/{plugin-id}/api/scan
*/

type pluginServer struct {
	cfg    *configStore
	zoraxy *ZoraxyAPI

	// csrfToken holds the latest X-Zoraxy-Csrf token Zoraxy forwarded to this
	// plugin. It is re-delivered on every proxied request, so the UI can fetch
	// it at runtime instead of depending on a possibly cached HTML page.
	csrfMu    sync.RWMutex
	csrfToken string
}

type ContainerInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	State       string `json:"state"`
	Status      string `json:"status"`
	NetworkMode string `json:"network_mode"`
}

type Candidate struct {
	HostID        string `json:"host_id"`
	HostName      string `json:"host_name"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	State         string `json:"state"`

	// Kind describes where the suggested upstream address comes from:
	//   published - docker host IP + published (mapped) port  [recommended]
	//   private   - container private IP on a docker network
	//   name      - container name, only usable if Zoraxy shares the network
	Kind        string `json:"kind"`
	Address     string `json:"address"`
	PrivatePort uint16 `json:"private_port,omitempty"`
	Note        string `json:"note,omitempty"`
	// Reachable is set after the scan by a TCP probe from the Zoraxy container.
	Reachable bool `json:"reachable"`
	// LinkedTo lists the proxy rules that already use this port as an upstream
	// origin (matched by port, since a swarm publish is reachable on every node).
	LinkedTo   []LinkedRule `json:"linked_to"`
	PublicPort uint16       `json:"public_port"`
}

// ServiceInfo is a swarm service with its task containers collapsed into a
// single entry. Task containers of the service are hidden from the plain
// container/candidate lists.
type ServiceInfo struct {
	HostID     string      `json:"host_id"`
	HostName   string      `json:"host_name"`
	Name       string      `json:"name"`
	Image      string      `json:"image"`
	Running    int         `json:"running"`
	Replicas   int         `json:"replicas"`
	Candidates []Candidate `json:"candidates"`
}

type HostResult struct {
	HostID        string          `json:"host_id"`
	HostName      string          `json:"host_name"`
	Endpoint      string          `json:"endpoint"`
	Online        bool            `json:"online"`
	Error         string          `json:"error,omitempty"`
	DaemonVersion string          `json:"daemon_version,omitempty"`
	Containers    []ContainerInfo `json:"containers"`
	Candidates    []Candidate     `json:"candidates"`
	Services      []ServiceInfo   `json:"services"`
}

func (s *pluginServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	s.noteCSRF(r)
	payload := map[string]interface{}{
		"hosts":                    s.cfg.hosts(),
		"polling_interval_seconds": s.cfg.pollingInterval(),
	}
	writeJSON(w, payload)
}

// noteCSRF records the CSRF token Zoraxy attaches to proxied requests as
// X-Zoraxy-Csrf header, so the frontend can use it for POST validation.
func (s *pluginServer) noteCSRF(r *http.Request) {
	t := r.Header.Get("X-Zoraxy-Csrf")
	if t == "" || t == "missing-csrf-token" {
		return
	}
	s.csrfMu.Lock()
	s.csrfToken = t
	s.csrfMu.Unlock()
}

func (s *pluginServer) handleGetCSRF(w http.ResponseWriter, r *http.Request) {
	s.noteCSRF(r)
	s.csrfMu.RLock()
	token := s.csrfToken
	s.csrfMu.RUnlock()
	writeJSON(w, map[string]string{"csrf_token": token})
}

func (s *pluginServer) handleUpsertHost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid form data")
		return
	}

	h := DockerHost{
		ID:              strings.TrimSpace(r.Form.Get("id")),
		Name:            strings.TrimSpace(r.Form.Get("name")),
		Endpoint:        strings.TrimSpace(r.Form.Get("endpoint")),
		TLS:             r.Form.Get("tls") == "true",
		InsecureSkipTLS: r.Form.Get("insecure_skip_tls") == "true",
		CACertPath:      strings.TrimSpace(r.Form.Get("ca_cert_path")),
		ClientCertPath:  strings.TrimSpace(r.Form.Get("client_cert_path")),
		ClientKeyPath:   strings.TrimSpace(r.Form.Get("client_key_path")),
		SuggestIP:       strings.TrimSpace(r.Form.Get("suggest_ip")),
	}
	if h.Name == "" {
		h.Name = h.Endpoint
	}
	if h.Endpoint == "" {
		writeError(w, "endpoint is required")
		return
	}
	if _, err := parseEndpoint(h); err != nil {
		writeError(w, err.Error())
		return
	}
	if h.ID == "" {
		h.ID = newHostID()
	}
	if err := s.cfg.upsertHost(h); err != nil {
		writeError(w, "failed to save config: "+err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"host_id": h.ID})
}

func (s *pluginServer) handleRemoveHost(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		writeError(w, "host id is required")
		return
	}
	if err := s.cfg.removeHost(id); err != nil {
		writeError(w, "failed to save config: "+err.Error())
		return
	}
	writeOK(w)
}

func (s *pluginServer) handleSetPolling(w http.ResponseWriter, r *http.Request) {
	parsed := 0
	fmt.Sscanf(r.FormValue("seconds"), "%d", &parsed)
	if err := s.cfg.setPollingInterval(parsed); err != nil {
		writeError(w, "failed to save config: "+err.Error())
		return
	}
	writeOK(w)
}

func (s *pluginServer) handlePingHost(w http.ResponseWriter, r *http.Request) {
	host := s.findHost(strings.TrimSpace(r.FormValue("id")))
	if host == nil {
		writeError(w, "host not found")
		return
	}
	version, err := host.Ping()
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"id": host.ID, "online": false, "error": err.Error(),
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"id": host.ID, "online": true, "daemon_version": version,
	})
}

// handleScan lists containers of all configured docker hosts and derives the
// candidate upstream addresses for each published/private port.
func (s *pluginServer) handleScan(w http.ResponseWriter, r *http.Request) {
	hosts := s.cfg.hosts()
	results := make([]HostResult, len(hosts))

	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h DockerHost) {
			defer wg.Done()
			results[i] = scanHost(h)
		}(i, h)
	}
	wg.Wait()

	// A plain container may bind the same host port that a swarm service also
	// publishes via the routing mesh. The swarm service owns that port, so drop
	// the plain-container candidate to avoid duplicate/confusing rows.
	svcPorts := map[uint16]bool{}
	for i := range results {
		for _, sv := range results[i].Services {
			for _, c := range sv.Candidates {
				svcPorts[c.PublicPort] = true
			}
		}
	}
	for i := range results {
		kept := results[i].Candidates[:0]
		for _, c := range results[i].Candidates {
			if c.Kind == "published" && c.ContainerID != "" && svcPorts[c.PublicPort] {
				continue
			}
			kept = append(kept, c)
		}
		results[i].Candidates = kept
	}

	// Probe reachability of every unique candidate address from the Zoraxy
	// container, so the UI can flag unreachable upstreams in red.
	var addrs []string
	for _, r := range results {
		for _, c := range r.Candidates {
			addrs = append(addrs, c.Address)
		}
		for _, sv := range r.Services {
			for _, c := range sv.Candidates {
				addrs = append(addrs, c.Address)
			}
		}
	}
	reach := probeTCP(addrs)
	for i := range results {
		for j := range results[i].Candidates {
			results[i].Candidates[j].Reachable = reach[results[i].Candidates[j].Address]
		}
		for k := range results[i].Services {
			for j := range results[i].Services[k].Candidates {
				results[i].Services[k].Candidates[j].Reachable = reach[results[i].Services[k].Candidates[j].Address]
			}
		}
	}

	// Flag candidates whose published port is already used as an upstream of a
	// proxy rule (matched by port, see ListLinkedOrigins). Only rules whose
	// origin points at one of the scanned docker hosts are considered, so
	// unrelated rules that reuse the same port on other machines are ignored.
	if s.zoraxy != nil {
		linked, err := s.zoraxy.ListLinkedOrigins()
		if err == nil {
			allowed := map[string]bool{}
			for _, h := range s.cfg.hosts() {
				allowed[strings.ToLower(h.Name)] = true
				if sa := h.suggestedAddress(); sa != "" {
					allowed[strings.ToLower(sa)] = true
				}
			}
			for i := range results {
				for j := range results[i].Candidates {
					results[i].Candidates[j].LinkedTo =
						filterLinked(linked[results[i].Candidates[j].PublicPort],
							strings.ToLower(results[i].HostName), allowed)
				}
				for k := range results[i].Services {
					for j := range results[i].Services[k].Candidates {
						results[i].Services[k].Candidates[j].LinkedTo =
							filterLinked(linked[results[i].Services[k].Candidates[j].PublicPort],
								strings.ToLower(results[i].HostName), allowed)
					}
				}
			}
		}
	}

	sort.Slice(results, func(a, b int) bool {
		return results[a].HostName < results[b].HostName
	})
	writeJSON(w, results)
}

// filterLinked keeps only rules whose origin points at one of the scanned
// docker hosts, deduplicated per rule domain. When the same rule uses the port
// on several nodes, the origin matching the candidate's own host is preferred
// so the candidate address itself remains the natural pick.
func filterLinked(rules []LinkedRule, candHost string, allowed map[string]bool) []LinkedRule {
	best := map[string]LinkedRule{}
	for _, r := range rules {
		oh := originHost(r.Origin)
		if !allowed[oh] {
			continue
		}
		cur, ok := best[r.Domain]
		if !ok {
			best[r.Domain] = r
			continue
		}
		if originHost(cur.Origin) != candHost && oh == candHost {
			best[r.Domain] = r
		}
	}
	if len(best) == 0 {
		return nil
	}
	domains := make([]string, 0, len(best))
	for d := range best {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	out := make([]LinkedRule, 0, len(domains))
	for _, d := range domains {
		out = append(out, best[d])
	}
	return out
}

func scanHost(h DockerHost) HostResult {
	res := HostResult{
		HostID:     h.ID,
		HostName:   h.Name,
		Endpoint:   h.Endpoint,
		Containers: []ContainerInfo{},
		Candidates: []Candidate{},
		Services:   []ServiceInfo{},
	}

	containers, err := h.ListContainers()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Online = true

	// Swarm task containers are grouped into services (detected via the
	// com.docker.swarm.service.name label) and excluded from the plain
	// container list, so a service with many replicas shows up only once.
	servicesMeta, _ := h.ListServices()
	metaByName := map[string]APIService{}
	for _, s := range servicesMeta {
		metaByName[s.Spec.Name] = s
	}

	taskGroups := map[string][]APIContainer{}
	plain := make([]APIContainer, 0, len(containers))
	for _, c := range containers {
		if svc := c.Labels["com.docker.swarm.service.name"]; svc != "" {
			taskGroups[svc] = append(taskGroups[svc], c)
			continue
		}
		plain = append(plain, c)
	}

	suggestAddr := h.suggestedAddress()
	hostIPs := map[string]bool{}
	if suggestAddr != "" {
		hostIPs[suggestAddr] = true
	}

	for _, c := range plain {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		res.Containers = append(res.Containers, ContainerInfo{
			ID:          c.ID,
			Name:        name,
			Image:       c.Image,
			State:       c.State,
			Status:      c.Status,
			NetworkMode: c.HostConfig.NetworkMode,
		})

		if c.HostConfig.NetworkMode == "none" {
			continue
		}

		// Published ports of the docker host (recommended for remote hosts)
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				continue
			}
			if len(hostIPs) == 0 {
				continue
			}
			addr := "0.0.0.0"
			if p.IP != "" {
				addr = p.IP
			}
			for ip := range hostIPs {
				if ip == "0.0.0.0" || ip == "::" {
					ip = addr
				}
				res.Candidates = append(res.Candidates, Candidate{
					HostID:        h.ID,
					HostName:      h.Name,
					ContainerID:   c.ID,
					ContainerName: name,
					Image:         c.Image,
					State:         c.State,
					Kind:          "published",
					Address:       formatAddr(ip, p.PublicPort),
					PrivatePort:   p.PrivatePort,
					PublicPort:    p.PublicPort,
					Note:          "hostIP:" + fmt.Sprint(p.PublicPort) + " (published)",
				})
			}
		}
	}

	// Docker may report the same port on multiple binding interfaces
	// (e.g. 0.0.0.0 and ::), so drop duplicate candidates per address.
	dedup := res.Candidates[:0]
	seen := map[string]bool{}
	for _, c := range res.Candidates {
		key := c.ContainerID + "|" + c.Kind + "|" + c.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		dedup = append(dedup, c)
	}
	res.Candidates = dedup

	// Swarm services (sorted by name)
	svcNames := make([]string, 0, len(taskGroups))
	for name := range taskGroups {
		svcNames = append(svcNames, name)
	}
	sort.Strings(svcNames)
	for _, name := range svcNames {
		res.Services = append(res.Services,
			buildService(h, name, taskGroups[name], metaByName[name]))
	}

	return res
}

// buildService collapses all task containers of a swarm service into a single
// ServiceInfo. Only published ports matter (they are NOT reported by
// /containers/json, so they come from the /services endpoint).
func buildService(h DockerHost, svcName string, tasks []APIContainer, meta APIService) ServiceInfo {
	info := ServiceInfo{
		HostID:     h.ID,
		HostName:   h.Name,
		Name:       svcName,
		Replicas:   len(tasks),
		Candidates: []Candidate{},
	}
	for _, t := range tasks {
		if t.State == "running" {
			info.Running++
		}
		if info.Image == "" {
			info.Image = t.Image
		}
	}

	suggestAddr := h.suggestedAddress()

	// Published ports of the service on the swarm host.
	for _, p := range meta.Endpoint.Ports {
		if p.PublishedPort == 0 || suggestAddr == "" {
			continue
		}
		info.Candidates = append(info.Candidates, Candidate{
			HostID:        h.ID,
			HostName:      h.Name,
			ContainerName: svcName,
			Image:         info.Image,
			State:         "running",
			Kind:          "published",
			Address:       formatAddr(suggestAddr, p.PublishedPort),
			PrivatePort:   p.TargetPort,
			PublicPort:    p.PublishedPort,
			Note:          "hostIP:" + fmt.Sprint(p.PublishedPort) + " (published)",
		})
	}

	// Drop duplicates per (kind, address).
	svcDedup := info.Candidates[:0]
	seen := map[string]bool{}
	for _, c := range info.Candidates {
		key := c.Kind + "|" + c.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		svcDedup = append(svcDedup, c)
	}
	info.Candidates = svcDedup

	return info
}

func (s *pluginServer) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.zoraxy.ListEndpoints()
	if err != nil {
		writeError(w, err.Error())
		return
	}
	writeJSON(w, endpoints)
}

func (s *pluginServer) handleApplyUpstream(w http.ResponseWriter, r *http.Request) {
	ep := strings.TrimSpace(r.FormValue("ep"))
	origin := strings.TrimSpace(r.FormValue("origin"))
	if ep == "" {
		writeError(w, "proxy endpoint is required")
		return
	}
	if origin == "" {
		writeError(w, "upstream origin is required")
		return
	}
	if err := s.zoraxy.AddUpstream(ep, origin); err != nil {
		writeError(w, err.Error())
		return
	}
	writeOK(w)
}

// handleSwitchPreview dry-runs a bulk host switch: it lists which proxy rules
// would be affected and how, without changing anything.
func (s *pluginServer) handleSwitchPreview(w http.ResponseWriter, r *http.Request) {
	from := strings.TrimSpace(r.FormValue("from"))
	to := strings.TrimSpace(r.FormValue("to"))
	if from == "" || to == "" {
		writeError(w, "both upstream hosts are required")
		return
	}
	if strings.EqualFold(from, to) {
		writeError(w, "source and target hosts must differ")
		return
	}
	preview, err := s.planUpstreamSwitch(from, to)
	if err != nil {
		writeError(w, err.Error())
		return
	}
	writeJSON(w, preview)
}

// handleBulkSwitch applies the upcoming upstream host switch to exactly the
// proxy rules selected in the UI ("rules" is a comma separated list of domains).
func (s *pluginServer) handleBulkSwitch(w http.ResponseWriter, r *http.Request) {
	from := strings.TrimSpace(r.FormValue("from"))
	to := strings.TrimSpace(r.FormValue("to"))
	rules := strings.TrimSpace(r.FormValue("rules"))
	if from == "" || to == "" {
		writeError(w, "both upstream hosts are required")
		return
	}
	if strings.EqualFold(from, to) {
		writeError(w, "source and target hosts must differ")
		return
	}
	selected := map[string]bool{}
	for _, part := range strings.Split(rules, ",") {
		if d := strings.TrimSpace(part); d != "" {
			selected[d] = true
		}
	}
	if len(selected) == 0 {
		writeError(w, "no proxy rules selected")
		return
	}
	writeJSON(w, s.executeUpstreamSwitch(from, to, selected))
}

func (s *pluginServer) findHost(id string) *DockerHost {
	for _, h := range s.cfg.hosts() {
		if h.ID == id {
			return &h
		}
	}
	return nil
}

func formatAddr(ip string, port uint16) string {
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		ip = "[" + ip + "]"
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func writeJSON(w http.ResponseWriter, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		writeError(w, "failed to marshal response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func writeOK(w http.ResponseWriter) {
	writeJSON(w, map[string]bool{"success": true})
}

func writeError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"error":` + mustQuote(msg) + `}`))
}

func mustQuote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
