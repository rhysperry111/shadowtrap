package api

import "net/http"

func (h *Handler) getMetaAPI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "shadowtrap",
		"version": apiVersion,
	})
}

func (h *Handler) getMetaServer(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "shadowtrap",
		"version": apiVersion,
	})
}
