# Docker Upstream Manager

Zoraxy plugin that scans Docker hosts for upstream candidates (published and
private ports) and applies them directly as upstream origins of a proxy rule.

The built-in "Pick from Docker Containers" feature in Zoraxy only:

- works inside the "New Proxy Rule" dialog (`rules.html`),
- talks to the **local** Docker daemon only (`/var/run/docker.sock` via
  `client.FromEnv` in `src/mod/dockerux/docker.go`), and
- does not run when editing the upstreams of an existing rule.

This plugin brings the same idea to a standalone page, and adds support for
**remote** Docker hosts (TCP/TLS) plus direct application to any proxy rule.

## Features

- Manage multiple Docker hosts:
  - `unix:///var/run/docker.sock` — local daemon
  - `tcp://192.168.1.10:2375` — plain Docker Engine API
  - `tcps://192.168.1.10:2376` or `https://...` — TLS with optional CA / client certificate
- Docker Engine API version negotiation (avoids "client version too new" errors,
  cf. zoraxy issue #639).
- Per container three kinds of upstream candidates:
  - **published** — Docker host IP + published (mapped) port (recommended for
    remote hosts)
  - **private** — container private IP on a docker bridge network
  - **name** — container name (only valid if Zoraxy shares the network)
- Pick the proxy rule you are editing, then either:
  - copy `host:port` to the clipboard, or
  - apply it directly as an upstream origin via the Zoraxy plugin API
    (`/plugin/api/proxy/upstream/add`).
- Search filter, running-only and unexposed(-name-only) toggles, optional
  auto-refresh polling.

## How it works

Plugins are independent processes talking to Zoraxy over loopback HTTP.

1. Zoraxy starts the plugin with `-configure=<json>` and grants an API key
   scoped to the endpoints declared in `PermittedAPIEndpoints` (`main.go`).
2. The plugin serves its UI at `/ui` (embedded in Zoraxy under
   `/plugin.ui/{id}/`).
3. The UI calls plugin-internal endpoints with **relative** paths
   (`uiRouter.HandleFunc("/api/...")` in `main.go`), so they work unchanged
   through Zoraxy's plugin UI reverse proxy.
4. `handlers.go - handleApplyUpstream` calls
   `POST /plugin/api/proxy/upstream/add` on the Zoraxy management API
   (ep = `RootOrMatchingDomain` of the selected rule, origin =
   `host:port`). `src/upstreams.go:64` in Zoraxy adds and persists it.

See also the example companion plugins in the Zoraxy repo:
`example/plugins/api-call-example`, `example/plugins/restful-example`.

## Requirements

- Zoraxy with plugin support (v3.0.7+, plugin UI proxying).
- Go 1.22+ to build.
- The Docker Engine API must be reachable. For **remote** hosts you typically
  have to configure the daemon to listen on TCP/TLS
  (`DOCKER_OPTS`/`daemon.json`), keep the port firewall-restricted, or use a
  tool like `docker context`.

## Build & install

```bash
go mod tidy
go build

# Validate the plugin metadata
./docker-port-selector -introspect
```

Copy the binary into a folder inside Zoraxy's plugin directory
(`-plugin`, default `./plugins`), refresh the plugin list in Zoraxy and enable
the plugin. The plugin stores its config as `config.json` next to the binary.

Running Zoraxy in a container? Mount the docker socket the same way the
built-in feature needs it:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

## Usage

1. Open **Plugins → Docker Port Selector**.
2. Add Docker host(s). For a **local** socket no Suggest IP is derived
   automatically — set "Suggest upstream IP" to the IP Zoraxy should use
   (e.g. the LAN IP of the host, or `host.docker.internal`).
3. Select the proxy rule you are currently editing under "Target Proxy Rule".
4. Hit "Scan all hosts"; per container/port you get the candidates.
5. Click **Set as upstream** to attach it to the selected rule, or **Copy**.

## Plugin source layout

```
go.mod                      module setup (stdlib only, no external deps)
main.go                     introspect spec + HTTP wiring (+ embed of ./web)
config.go                   docker host config + JSON persistence (config.json)
dockerclient.go             minimal Docker Engine API client (unix/tcp/tls,
                            version negotiation, /containers/json)
zoraxyapi.go                Zoraxy plugin API client (proxy/list, upstream/*
                            add/update/remove)
switch.go                   bulk upstream switch: plan (preview) + filtered
                            execution + origin parsing (switch_test.go)
handlers.go                 plugin-internal JSON API (/ui/api/*)
web/index.html              the embedded plugin UI
mod/zoraxy_plugin/          zoraxy_plugin library (copied from Zoraxy, LGPL)
```

## Notes / limitations

- The plugin UI is a separate page; Zoraxy's proxy rule editor itself cannot be
  extended by a plugin (no hook exists in `rules.html` / `upstreams.html`).
  "Set as upstream" is the closest integration: select the target rule in the
  plugin page, then apply the candidate.
- Published-port suggestions for a `unix://` host are only shown when
  "Suggest upstream IP" is set — a plain socket cannot tell which address
  Zoraxy should use to reach the host.
- Reads `/containers/json?all=1`: stopped containers appear under the
  name-only kind unless "Show unexposed" is enabled.

## Link detection & reachability

The scan output groups published candidates by their link state:

- **Linked** — a Zoraxy proxy rule already has that `host:port` as an upstream
  origin (entry is a live link, color-coded).
- Clicking a linked rule row opens the Zoraxy rule editor directly (deep link
  into the `httprp` tab, domain encoded as hex).
- Unlinked candidates of plain (non-swarm) containers are suppressed when a
  swarm service already publishes the same port.
- Each host card shows a reachability dot (green/red) checked with a quick
  TCP probe to the Docker Engine API endpoint.

## Bulk upstream switch

Two-stage failover helper for when a Docker host dies:

1. Pick `from` and `to` hosts, press **Show affected rules** — this is a
   read-only preview listing every proxy rule whose upstreams would move to
   the target host (ports unchanged).
2. Tick the rules you actually want to switch (or default-select all), then
   press **Switch selected rules**.

Only the selected rules are touched. The switch is done entirely through the
Zoraxy plugin API (`proxy/upstream/update` / `proxy/upstream/remove`), so the
**dead host is never contacted**. Origins whose target (`to:` same port)
already exists in a rule are dropped instead of renamed, keeping the target
active. The result list reports switched / skipped / errors per rule.

## License

This plugin is licensed under the AGPL-3.0 license (see `LICENSE`). The bundled
`mod/zoraxy_plugin` library is copied as-is from the Zoraxy project and
remains under its original LGPL license (see `mod/zoraxy_plugin/LICENSE`).