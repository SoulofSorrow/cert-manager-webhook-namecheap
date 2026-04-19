package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/yourusername/cert-manager-webhook-namecheap/pkg/dryrun"
	"github.com/yourusername/cert-manager-webhook-namecheap/pkg/namecheap"
	"github.com/yourusername/cert-manager-webhook-namecheap/pkg/solver"
	"k8s.io/klog/v2"
)

// GroupName is the Kubernetes API group for this webhook.
// Must match the groupName in the ClusterIssuer solver config.
var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		GroupName = "acme.yourdomain.com"
	}

	// Start the dry run HTTP endpoint on a separate port so it is
	// accessible without TLS and does not interfere with the webhook server.
	go startDryRunServer()

	cmd.RunWebhookServer(GroupName, solver.New())
}

// startDryRunServer listens on :8080 and exposes a /dryrun endpoint.
//
// Usage:
//
//	kubectl port-forward -n cert-manager svc/cert-manager-webhook-namecheap 8080:8080
//	curl "http://localhost:8080/dryrun?domain=groot.rocks"
//	curl "http://localhost:8080/dryrun?domain=groot.rocks&format=json"
func startDryRunServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/dryrun", handleDryRun)
	// /ready is for the dry-run HTTP server itself, not for the main
	// webhook server (which exposes /healthz on port 443 via cert-manager's cmd.RunWebhookServer).
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	addr := ":8080"
	klog.Infof("dry run server listening on %s", addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		klog.Errorf("dry run server error: %v", err)
	}
}

func handleDryRun(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "missing query parameter: domain", http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format") // "json" or default text

	apiUser := os.Getenv("NAMECHEAP_API_USER")
	apiKey := os.Getenv("NAMECHEAP_API_KEY")
	username := os.Getenv("NAMECHEAP_USERNAME")

	if apiUser == "" || apiKey == "" {
		http.Error(w, "NAMECHEAP_API_USER and NAMECHEAP_API_KEY must be set", http.StatusInternalServerError)
		return
	}
	if username == "" {
		username = apiUser
	}

	client := namecheap.NewClient(apiUser, apiKey, username)
	report := dryrun.Run(client, domain)

	klog.Infof("dry run for domain=%s ok=%v", domain, report.OK())

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		if !report.OK() {
			w.WriteHeader(http.StatusBadGateway)
		}
		type jsonResult struct {
			Name    string `json:"name"`
			OK      bool   `json:"ok"`
			Detail  string `json:"detail"`
			Elapsed string `json:"elapsed"`
		}
		type jsonReport struct {
			Domain  string       `json:"domain"`
			OK      bool         `json:"ok"`
			Results []jsonResult `json:"results"`
		}
		resp := jsonReport{Domain: domain, OK: report.OK()}
		for _, res := range report.Results {
			resp.Results = append(resp.Results, jsonResult{
				Name:    res.Name,
				OK:      res.OK,
				Detail:  res.Detail,
				Elapsed: res.Elapsed.Round(time.Millisecond).String(),
			})
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Plain text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !report.OK() {
		w.WriteHeader(http.StatusBadGateway)
	}
	fmt.Fprint(w, report.String())
}
