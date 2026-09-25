package main

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	plugin "zoraxy-plugin-docker-port-selector/mod/zoraxy_plugin"
)

//go:embed web
var webFS embed.FS

const (
	PLUGIN_ID   = "de.mcfetz.zoraxy.docker_upstream_manager"
	PLUGIN_NAME = "Docker Upstream Manager"
	UI_PATH     = "/ui"
)

func main() {
	runtimeCfg := serveIntrospectAndConfigure()

	// The plugin runs with its own folder as working directory, so all
	// persistent state lives next to the binary.
	workDir, err := os.Getwd()
	if err != nil {
		workDir = "."
	}
	store, err := newConfigStore(filepath.Join(workDir, configFileName))
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	zoraxy := NewZoraxyAPI(runtimeCfg.ZoraxyPort, runtimeCfg.APIKey)
	server := &pluginServer{
		cfg:    store,
		zoraxy: zoraxy,
	}

	uiRouter := plugin.NewPluginEmbedUIRouter(PLUGIN_ID, &webFS, "/web", UI_PATH)

	mux := http.NewServeMux()

	// Plugin-internal JSON API, reachable from the UI via relative paths
	uiRouter.HandleFunc("/api/config", server.handleGetConfig, mux)
	uiRouter.HandleFunc("/api/config/host", server.handleUpsertHost, mux)
	uiRouter.HandleFunc("/api/config/host/remove", server.handleRemoveHost, mux)
	uiRouter.HandleFunc("/api/config/polling", server.handleSetPolling, mux)
	uiRouter.HandleFunc("/api/csrf", server.handleGetCSRF, mux)
	uiRouter.HandleFunc("/api/host/ping", server.handlePingHost, mux)
	uiRouter.HandleFunc("/api/scan", server.handleScan, mux)
	uiRouter.HandleFunc("/api/endpoints", server.handleListEndpoints, mux)
	uiRouter.HandleFunc("/api/apply", server.handleApplyUpstream, mux)
	uiRouter.HandleFunc("/api/upstream/switch/preview", server.handleSwitchPreview, mux)
	uiRouter.HandleFunc("/api/upstream/switch", server.handleBulkSwitch, mux)

	// Serve the embedded UI through the render handler. It is wrapped here so
	// the CSRF token placeholder gets populated and the HTML is never cached
	// (otherwise a stale page without the token would keep failing with 403).
	h := uiRouter.Handler()
	mux.Handle("/ui/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	}))

	uiRouter.RegisterTerminateHandler(func() {
		fmt.Println(PLUGIN_NAME + " terminating")
	}, nil)

	serverAddr := fmt.Sprintf("127.0.0.1:%d", runtimeCfg.Port)
	fmt.Printf("Starting %s on %s\n", PLUGIN_NAME, serverAddr)
	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		fmt.Println("Server stopped:", err)
		os.Exit(1)
	}
}

// serveIntrospectAndConfigure prints the introspect payload (when started with
// -introspect) or returns the ConfigureSpec provided by Zoraxy.
func serveIntrospectAndConfigure() *plugin.ConfigureSpec {
	spec := &plugin.IntroSpect{
		ID:            PLUGIN_ID,
		Name:          PLUGIN_NAME,
		Author:        "Daniel Heise",
		AuthorContact: "post@mcfetz.de",
		Description:   "Scans Docker hosts for published ports, applies them as upstreams of Zoraxy proxy rules, deep-links linked rules and switches all upstreams to another host in case of failure.",
		URL:           "https://github.com/mcfetz/zoraxy-docker-upstream-manager",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  0,
		VersionMinor:  1,
		VersionPatch:  0,

		UIPath: UI_PATH,

		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{
			{
				Method:   http.MethodGet,
				Endpoint: "/plugin/api/proxy/list",
				Reason:   "List proxy rules so the selected docker upstream can be applied to the endpoint being edited",
			},
			{
				Method:   http.MethodGet,
				Endpoint: "/plugin/api/proxy/upstream/list",
				Reason:   "Detect which published ports are already linked to a proxy rule",
			},
			{
				Method:   http.MethodPost,
				Endpoint: "/plugin/api/proxy/upstream/add",
				Reason:   "Add the selected docker container port as an upstream origin of a proxy rule",
			},
			{
				Method:   http.MethodPost,
				Endpoint: "/plugin/api/proxy/upstream/update",
				Reason:   "Bulk host switch: rewrite upstream origins from one docker host to another",
			},
			{
				Method:   http.MethodPost,
				Endpoint: "/plugin/api/proxy/upstream/remove",
				Reason:   "Bulk host switch: drop upstream origins pointing at a failed docker host",
			},
		},
	}

	cfg, err := plugin.ServeAndRecvSpec(spec)
	if err != nil {
		fmt.Printf("Error serving introspect: %v\n", err)
		os.Exit(1)
	}
	return cfg
}
