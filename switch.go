package main

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

// originOwner says whether a published port on a docker host belongs to a
// swarm service or to a plain (non-swarm) container.
type originOwner struct {
	Kind string `json:"kind"` // service | container
	Name string `json:"name"`
}

// switchAction describes one upstream origin that a bulk host switch would
// change. The action is only ever executed for rules explicitly selected in
// the UI (plan-then-execute).
type switchAction struct {
	Domain    string      `json:"domain"`
	Origin    string      `json:"origin"`
	NewOrigin string      `json:"new_origin,omitempty"`
	Kind      string      `json:"kind"` // update | drop
	Active    bool        `json:"active"`
	Owner     originOwner `json:"owner"` // service/container of the current port on the source host
}

// planRule groups the switchable actions of one proxy rule.
type planRule struct {
	Domain  string         `json:"domain"`
	Actions []switchAction `json:"actions"`
}

// switchPreview is the dry-run result of a bulk host switch.
type switchPreview struct {
	From  string     `json:"from"`
	To    string     `json:"to"`
	Rules []planRule `json:"rules"`
}

// switchDetail describes one upstream origin that was switched, skipped or
// failed during an executed bulk host switch.
type switchDetail struct {
	Domain string `json:"domain"`
	Origin string `json:"origin"`
	Detail string `json:"detail"`
}

// bulkSwitchResult is the machine readable result of an executed bulk host
// switch. Only the previously selected rules are touched.
type bulkSwitchResult struct {
	From     string         `json:"from"`
	To       string         `json:"to"`
	Switched []switchDetail `json:"switched"`
	Skipped  []switchDetail `json:"skipped"`
	Errors   []switchDetail `json:"errors"`
}

// planUpstreamSwitch computes, without mutating anything, which upstream
// origins of which proxy rules would move from fromHost to toHost.
func (s *pluginServer) planUpstreamSwitch(fromHost, toHost string) (*switchPreview, error) {
	endpoints, err := s.zoraxy.ListEndpoints()
	if err != nil {
		return nil, err
	}
	preview := &switchPreview{From: fromHost, To: toHost, Rules: []planRule{}}

	// Classify the currently published ports of the source host (service vs
	// container) so each affected origin can be tagged. Unknown when the host
	// is not configured or offline - the switch itself never touches it.
	var owners map[string]originOwner
	for _, h := range s.cfg.hosts() {
		if strings.EqualFold(h.Name, fromHost) {
			owners = s.hostPortOwners(h)
			break
		}
	}

	const max = 8
	sem := make(chan struct{}, max)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var actions []switchAction
			origins, err := s.zoraxy.ListUpstreams(domain)
			if err != nil {
				return
			}
			existing := map[string]bool{}
			for _, u := range origins {
				existing[strings.ToLower(strings.TrimSpace(u.OriginIpOrDomain))] = true
			}
			for _, u := range origins {
				oldOrigin := strings.TrimSpace(u.OriginIpOrDomain)
				newOrigin, matched := switchOriginHost(oldOrigin, fromHost, toHost)
				if !matched || strings.EqualFold(oldOrigin, newOrigin) {
					continue
				}
				kind := "update"
				if existing[strings.ToLower(newOrigin)] {
					// The target already exists in this rule: only the dead host
					// origin would be dropped (target stays/gets active).
					if !u.Active {
						continue
					}
					kind = "drop"
					newOrigin = ""
				}
				actions = append(actions, switchAction{
					Domain:    domain,
					Origin:    oldOrigin,
					NewOrigin: newOrigin,
					Kind:      kind,
					Active:    u.Active,
					Owner:     owners[strconv.Itoa(int(originPort(oldOrigin)))],
				})
			}
			if len(actions) == 0 {
				return
			}
			sort.Slice(actions, func(i, j int) bool { return actions[i].Origin < actions[j].Origin })
			mu.Lock()
			preview.Rules = append(preview.Rules, planRule{Domain: domain, Actions: actions})
			mu.Unlock()
		}(ep.RootOrMatchingDomain)
	}
	wg.Wait()
	sort.Slice(preview.Rules, func(i, j int) bool { return preview.Rules[i].Domain < preview.Rules[j].Domain })
	return preview, nil
}

// executeUpstreamSwitch applies the previously planned host switch to exactly
// the given proxy rules (domains). The source host may be dead; all work is
// done through the Zoraxy plugin API so the offline node is never contacted.
func (s *pluginServer) executeUpstreamSwitch(fromHost, toHost string, domains map[string]bool) *bulkSwitchResult {
	res := &bulkSwitchResult{
		From:     fromHost,
		To:       toHost,
		Switched: []switchDetail{},
		Skipped:  []switchDetail{},
		Errors:   []switchDetail{},
	}

	endpoints, err := s.zoraxy.ListEndpoints()
	if err != nil {
		res.Errors = append(res.Errors, switchDetail{Detail: "list proxy rules: " + err.Error()})
		return res
	}

	const max = 8
	sem := make(chan struct{}, max)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		if !domains[ep.RootOrMatchingDomain] {
			continue
		}
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var switched, skipped, errs []switchDetail
			origins, err := s.zoraxy.ListUpstreams(domain)
			if err != nil {
				errs = append(errs, switchDetail{Origin: domain, Detail: err.Error()})
			}
			existing := map[string]bool{}
			existingActive := map[string]bool{}
			for _, u := range origins {
				key := strings.ToLower(strings.TrimSpace(u.OriginIpOrDomain))
				existing[key] = true
				existingActive[key] = u.Active
			}
			for _, u := range origins {
				oldOrigin := strings.TrimSpace(u.OriginIpOrDomain)
				newOrigin, matched := switchOriginHost(oldOrigin, fromHost, toHost)
				if !matched {
					continue
				}
				newKey := strings.ToLower(newOrigin)

				if strings.EqualFold(oldOrigin, newKey) {
					skipped = append(skipped, switchDetail{Domain: domain, Origin: oldOrigin, Detail: "already points at target"})
					continue
				}

				if existing[newKey] {
					if !u.Active {
						skipped = append(skipped, switchDetail{Domain: domain, Origin: oldOrigin, Detail: newOrigin + " already exists"})
						continue
					}
					// Target already lives inside this rule. Drop the dead host
					// origin and make sure the remaining one is still active.
					if !existingActive[newKey] {
						if err := s.zoraxy.UpdateUpstream(domain, newOrigin, newOrigin, true); err != nil {
							errs = append(errs, switchDetail{Domain: domain, Origin: oldOrigin, Detail: "activate " + newOrigin + ": " + err.Error()})
						}
					}
					if err := s.zoraxy.RemoveUpstream(domain, oldOrigin); err != nil {
						errs = append(errs, switchDetail{Domain: domain, Origin: oldOrigin, Detail: "remove: " + err.Error()})
					} else {
						switched = append(switched, switchDetail{Domain: domain, Origin: oldOrigin, Detail: "dropped, " + newOrigin + " stays active"})
					}
					continue
				}

				if err := s.zoraxy.UpdateUpstream(domain, oldOrigin, newOrigin, u.Active); err != nil {
					errs = append(errs, switchDetail{Domain: domain, Origin: oldOrigin, Detail: err.Error()})
					continue
				}
				switched = append(switched, switchDetail{Domain: domain, Origin: oldOrigin, Detail: "-> " + newOrigin})
			}

			mu.Lock()
			res.Switched = append(res.Switched, switched...)
			res.Skipped = append(res.Skipped, skipped...)
			res.Errors = append(res.Errors, errs...)
			mu.Unlock()
		}(ep.RootOrMatchingDomain)
	}
	wg.Wait()
	sort.Slice(res.Switched, func(i, j int) bool { return res.Switched[i].Domain < res.Switched[j].Domain })
	sort.Slice(res.Errors, func(i, j int) bool { return res.Errors[i].Domain < res.Errors[j].Domain })
	return res
}

// switchOriginHost rewrites the host part of an upstream origin (host, host:port
// or scheme://host:port/path) from fromHost to toHost. The port and path are
// kept. It returns ("", false) when the origin does not point at fromHost.
func switchOriginHost(origin, fromHost, toHost string) (string, bool) {
	o := strings.TrimSpace(origin)
	if o == "" {
		return "", false
	}
	scheme := ""
	if i := strings.Index(o, "://"); i >= 0 {
		scheme = o[:i+3]
		o = o[i+3:]
	}
	path := ""
	if i := strings.Index(o, "/"); i >= 0 {
		path = o[i:]
		o = o[:i]
	}
	host, port, hasPort := splitHostPort(o)
	if !strings.EqualFold(host, fromHost) {
		return "", false
	}
	rebuilt := toHost
	if hasPort {
		if strings.Contains(toHost, ":") && !strings.HasPrefix(toHost, "[") {
			toHost = "[" + toHost + "]"
		}
		rebuilt = toHost + ":" + port
	}
	return scheme + rebuilt + path, true
}

// splitHostPort splits a host[:port] pair. IPv6 literals must be bracketed.
func splitHostPort(s string) (host, port string, hasPort bool) {
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			host = s[1:i]
			if rest := s[i+1:]; strings.HasPrefix(rest, ":") {
				return host, rest[1:], true
			}
			return host, "", false
		}
		return s, "", false
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// hostPortOwners maps "published port number" -> owner info for one docker
// host. Swarm service ports win over plain-container ports (a container may
// not bind a port the routing mesh already owns). The map is empty when the
// host is not reachable; the plugin never blocks a switch on this data.
func (s *pluginServer) hostPortOwners(h DockerHost) map[string]originOwner {
	owners := map[string]originOwner{}

	var services []APIService
	var containers []APIContainer

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		services, _ = h.ListServices()
	}()
	go func() {
		defer wg.Done()
		containers, _ = h.ListContainers()
	}()
	wg.Wait()

	for _, sv := range services {
		for _, p := range sv.Endpoint.Ports {
			owners[strconv.Itoa(int(p.PublishedPort))] = originOwner{Kind: "service", Name: sv.Spec.Name}
		}
	}
	for _, c := range containers {
		if _, isTask := c.Labels["com.docker.swarm.service.name"]; isTask {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				continue
			}
			key := strconv.Itoa(int(p.PublicPort))
			if _, ok := owners[key]; ok {
				continue // swarm service owns this port
			}
			owners[key] = originOwner{Kind: "container", Name: name}
		}
	}
	return owners
}
