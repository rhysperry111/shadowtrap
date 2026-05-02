// Package api implements the ShadowTrap HTTP API as specified in
// openapi.yaml, gated by an api_key header and a role-based ACL.
package api

import (
	"encoding/json"
	"net/http"

	"shadowtrap/controller/db"
	"shadowtrap/controller/potscheduler"
)

const apiVersion = "1.0.0"

// Handler is the root HTTP handler. It holds references to shared
// services so route handlers can reach them through receivers.
type Handler struct {
	queries   *db.Queries
	scheduler *potscheduler.Scheduler

	// masterKey is the in-memory admin key from --api-key. It's never
	// stored in the database — it exists for bootstrapping.
	masterKey string
}

func New(queries *db.Queries, scheduler *potscheduler.Scheduler, masterKey string) http.Handler {
	h := &Handler{
		queries:   queries,
		scheduler: scheduler,
		masterKey: masterKey,
	}

	read := h.require(PermRead)
	write := h.require(PermWrite)
	admin := h.require(PermAdmin)

	mux := http.NewServeMux()

	// Meta — public, no auth.
	mux.HandleFunc("GET /api/meta/api", h.getMetaAPI)
	mux.HandleFunc("GET /api/meta/server", h.getMetaServer)

	// Pots (read-only — pots are managed by the scheduler).
	mux.HandleFunc("GET /api/info/pots", read(h.getPots))
	mux.HandleFunc("GET /api/info/pots/{id}", read(h.getPot))

	// Images (read-only — registered at startup).
	mux.HandleFunc("GET /api/settings/pots/images", read(h.getImages))
	mux.HandleFunc("GET /api/settings/pots/images/{id}", read(h.getImage))

	// Deployments.
	mux.HandleFunc("GET /api/settings/pots/deployments", read(h.getDeployments))
	mux.HandleFunc("POST /api/settings/pots/deployments", write(h.createDeployment))
	mux.HandleFunc("GET /api/settings/pots/deployments/{id}", read(h.getDeployment))
	mux.HandleFunc("PUT /api/settings/pots/deployments/{id}", write(h.updateDeployment))
	mux.HandleFunc("DELETE /api/settings/pots/deployments/{id}", write(h.deleteDeployment))

	// Network configuration.
	mux.HandleFunc("GET /api/settings/network/host", read(h.getNetworkHost))
	mux.HandleFunc("PUT /api/settings/network/host", write(h.putNetworkHost))

	mux.HandleFunc("GET /api/settings/network/interfaces", read(h.getInterfaces))
	mux.HandleFunc("GET /api/settings/network/interfaces/{id}", read(h.getInterface))
	mux.HandleFunc("PUT /api/settings/network/interfaces/{id}", write(h.putInterface))

	mux.HandleFunc("GET /api/settings/network/networks", read(h.getNetworks))
	mux.HandleFunc("POST /api/settings/network/networks", write(h.createNetwork))
	mux.HandleFunc("GET /api/settings/network/networks/{id}", read(h.getNetwork))
	mux.HandleFunc("PUT /api/settings/network/networks/{id}", write(h.putNetwork))
	mux.HandleFunc("DELETE /api/settings/network/networks/{id}", write(h.deleteNetwork))

	// API key management — admin only.
	mux.HandleFunc("GET /api/settings/auth/keys", admin(h.listAPIKeys))
	mux.HandleFunc("POST /api/settings/auth/keys", admin(h.createAPIKey))
	mux.HandleFunc("DELETE /api/settings/auth/keys/{name}", admin(h.deleteAPIKey))

	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errType, info string) {
	writeJSON(w, code, map[string]string{"type": errType, "info": info})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
