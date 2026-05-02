package api

import (
	"fmt"
	"net/http"

	"shadowtrap/controller/db"
)

func (h *Handler) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.queries.ListAPIKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}

	infos := make([]apiKeyInfo, len(keys))
	for i, key := range keys {
		infos[i] = apiKeyToInfo(key)
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": infos})
}

func (h *Handler) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_BODY", err.Error())
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAMETER", "name is required")
		return
	}
	if !ValidRole(body.Role) {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAMETER",
			fmt.Sprintf("role must be one of: %v", ValidRoles()))
		return
	}

	rawKey, hash, err := GenerateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", "key generation failed")
		return
	}

	created, err := h.queries.CreateAPIKey(r.Context(), db.CreateAPIKeyParams{
		KeyHash: hash,
		Name:    body.Name,
		Role:    body.Role,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "ERR_DUPLICATE", "a key with that name already exists")
		return
	}

	// rawKey is returned only here; it isn't stored and can't be recovered.
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       created.Name,
		"role":       created.Role,
		"key":        rawKey,
		"created_at": created.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

func (h *Handler) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.queries.DeleteAPIKeyByName(r.Context(), name); err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "key not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}
