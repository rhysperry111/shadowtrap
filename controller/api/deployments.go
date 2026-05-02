package api

import (
	"net/http"

	"shadowtrap/controller/db"
)

type deploymentImageRef struct {
	ID string `json:"id"`
}

type deploymentNetworkRef struct {
	ID string `json:"id"`
}

type deploymentJSON struct {
	ID         string                 `json:"id"`
	Active     bool                   `json:"active"`
	Count      int32                  `json:"count"`
	Image      []deploymentImageRef   `json:"image"`
	Network    []deploymentNetworkRef `json:"network"`
	IPAM       string                 `json:"ipam,omitempty"`
	TTLMinutes int32                  `json:"ttl_minutes"`
}

func deploymentToJSON(d db.Deployment) deploymentJSON {
	images := make([]deploymentImageRef, len(d.ImageIds))
	for i, id := range d.ImageIds {
		images[i] = deploymentImageRef{ID: id}
	}

	networks := make([]deploymentNetworkRef, len(d.NetworkIds))
	for i, id := range d.NetworkIds {
		networks[i] = deploymentNetworkRef{ID: id}
	}

	return deploymentJSON{
		ID:         d.ID,
		Active:     d.Active,
		Count:      d.Count,
		Image:      images,
		Network:    networks,
		IPAM:       d.Ipam,
		TTLMinutes: d.TtlMinutes,
	}
}

// paramsFromJSON converts the wire form to create-side query params.
// IPAM defaults to "sweep" — the only allocator that needs no external
// system — when the caller leaves it blank.
func paramsFromJSON(body deploymentJSON) db.CreateDeploymentParams {
	imageIDs := make([]string, len(body.Image))
	for i, ref := range body.Image {
		imageIDs[i] = ref.ID
	}

	networkIDs := make([]string, len(body.Network))
	for i, ref := range body.Network {
		networkIDs[i] = ref.ID
	}

	ipam := body.IPAM
	if ipam == "" {
		ipam = "sweep"
	}

	return db.CreateDeploymentParams{
		ID:         body.ID,
		Active:     body.Active,
		Count:      body.Count,
		ImageIds:   imageIDs,
		NetworkIds: networkIDs,
		Ipam:       ipam,
		TtlMinutes: body.TTLMinutes,
	}
}

func (h *Handler) getDeployments(w http.ResponseWriter, r *http.Request) {
	deployments, err := h.queries.ListDeployments(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}

	out := make([]deploymentJSON, len(deployments))
	for i, d := range deployments {
		out[i] = deploymentToJSON(d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deployments": out})
}

func (h *Handler) getDeployment(w http.ResponseWriter, r *http.Request) {
	deployment, err := h.queries.GetDeployment(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "deployment not found")
		return
	}
	writeJSON(w, http.StatusOK, deploymentToJSON(deployment))
}

func (h *Handler) createDeployment(w http.ResponseWriter, r *http.Request) {
	var body deploymentJSON
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_BODY", err.Error())
		return
	}
	if body.ID == "" {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAMETER", "id is required")
		return
	}

	created, err := h.queries.CreateDeployment(r.Context(), paramsFromJSON(body))
	if err != nil {
		writeError(w, http.StatusConflict, "ERR_DUPLICATE", "deployment already exists")
		return
	}
	writeJSON(w, http.StatusOK, deploymentToJSON(created))
}

func (h *Handler) updateDeployment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body deploymentJSON
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_BODY", err.Error())
		return
	}

	params := paramsFromJSON(body)
	updated, err := h.queries.UpdateDeployment(r.Context(), db.UpdateDeploymentParams{
		ID:         id,
		Active:     params.Active,
		Count:      params.Count,
		ImageIds:   params.ImageIds,
		NetworkIds: params.NetworkIds,
		Ipam:       params.Ipam,
		TtlMinutes: params.TtlMinutes,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "deployment not found")
		return
	}
	writeJSON(w, http.StatusOK, deploymentToJSON(updated))
}

func (h *Handler) deleteDeployment(w http.ResponseWriter, r *http.Request) {
	if err := h.queries.DeleteDeployment(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "deployment not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}
