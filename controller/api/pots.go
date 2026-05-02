package api

import (
	"net/http"

	"shadowtrap/controller/db"
)

type potJSON struct {
	ID            string `json:"id"`
	Deployment    string `json:"deployment"`
	Image         string `json:"image"`
	Network       string `json:"network"`
	Discriminator int32  `json:"discriminator"`
	Status        string `json:"status"`
	IP            string `json:"ip"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	CredHint      string `json:"cred_hint,omitempty"`
}

func potToJSON(p db.Pot) potJSON {
	expiresAt := ""
	if p.ExpiresAt != nil {
		expiresAt = p.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return potJSON{
		ID:            p.ID,
		Deployment:    p.DeploymentID,
		Image:         p.ImageID,
		Network:       p.NetworkID,
		Discriminator: p.Discriminator,
		Status:        p.Status,
		IP:            p.Ip,
		ExpiresAt:     expiresAt,
		CredHint:      p.CredHint,
	}
}

func (h *Handler) getPots(w http.ResponseWriter, r *http.Request) {
	pots, err := h.queries.ListPots(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}

	out := make([]potJSON, len(pots))
	for i, p := range pots {
		out[i] = potToJSON(p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"pots": out})
}

func (h *Handler) getPot(w http.ResponseWriter, r *http.Request) {
	pot, err := h.queries.GetPot(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "pot not found")
		return
	}
	writeJSON(w, http.StatusOK, potToJSON(pot))
}
