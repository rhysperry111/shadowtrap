package api

import (
	"net/http"

	"shadowtrap/controller/db"
)

// Host network configuration.

type networkHostJSON struct {
	Network       string `json:"network"`
	Mode          string `json:"mode"`
	StaticIP      string `json:"static_ip,omitempty"`
	StaticGateway string `json:"static_gateway,omitempty"`
	StaticDNS     string `json:"static_dns,omitempty"`
}

func (h *Handler) getNetworkHost(w http.ResponseWriter, r *http.Request) {
	host, err := h.queries.GetHost(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, networkHostJSON{Mode: "dhcp"})
		return
	}
	writeJSON(w, http.StatusOK, networkHostJSON{
		Network:       host.Network,
		Mode:          host.Mode,
		StaticIP:      host.StaticIp,
		StaticGateway: host.StaticGateway,
		StaticDNS:     host.StaticDns,
	})
}

func (h *Handler) putNetworkHost(w http.ResponseWriter, r *http.Request) {
	var body networkHostJSON
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_BODY", err.Error())
		return
	}

	err := h.queries.UpsertHost(r.Context(), db.UpsertHostParams{
		Network:       body.Network,
		Mode:          body.Mode,
		StaticIp:      body.StaticIP,
		StaticGateway: body.StaticGateway,
		StaticDns:     body.StaticDNS,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// Interfaces.

type interfaceJSON struct {
	ID             string `json:"id"`
	Enabled        bool   `json:"enabled"`
	Link           bool   `json:"link"`
	Mode           string `json:"mode,omitempty"`
	AggregateGroup string `json:"aggregate_group,omitempty"`
}

func ifaceToJSON(iface db.Interface) interfaceJSON {
	return interfaceJSON{
		ID:             iface.ID,
		Enabled:        iface.Enabled,
		Link:           iface.Link,
		Mode:           iface.Mode,
		AggregateGroup: iface.AggregateGroup,
	}
}

func (h *Handler) getInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := h.queries.ListInterfaces(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}

	out := make([]interfaceJSON, len(interfaces))
	for i, iface := range interfaces {
		out[i] = ifaceToJSON(iface)
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": out})
}

func (h *Handler) getInterface(w http.ResponseWriter, r *http.Request) {
	iface, err := h.queries.GetInterface(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "interface not found")
		return
	}
	writeJSON(w, http.StatusOK, ifaceToJSON(iface))
}

func (h *Handler) putInterface(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body interfaceJSON
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_BODY", err.Error())
		return
	}

	err := h.queries.UpsertInterface(r.Context(), db.UpsertInterfaceParams{
		ID:             id,
		Enabled:        body.Enabled,
		Link:           body.Link,
		Mode:           body.Mode,
		AggregateGroup: body.AggregateGroup,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}

	body.ID = id
	writeJSON(w, http.StatusOK, body)
}

// Networks.

type networkJSON struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"`
	Type      string `json:"type,omitempty"`
	VLANID    int32  `json:"vlan_id,omitempty"`
	Subnet    string `json:"subnet,omitempty"`
}

func networkToJSON(network db.Network) networkJSON {
	return networkJSON{
		ID:        network.ID,
		Enabled:   network.Enabled,
		Interface: network.InterfaceID,
		Type:      network.Type,
		VLANID:    network.VlanID,
		Subnet:    network.Subnet,
	}
}

func (h *Handler) getNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := h.queries.ListNetworks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}

	out := make([]networkJSON, len(networks))
	for i, network := range networks {
		out[i] = networkToJSON(network)
	}
	writeJSON(w, http.StatusOK, map[string]any{"networks": out})
}

func (h *Handler) getNetwork(w http.ResponseWriter, r *http.Request) {
	network, err := h.queries.GetNetwork(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "network not found")
		return
	}
	writeJSON(w, http.StatusOK, networkToJSON(network))
}

func (h *Handler) createNetwork(w http.ResponseWriter, r *http.Request) {
	var body networkJSON
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_BODY", err.Error())
		return
	}
	if body.ID == "" || body.Interface == "" {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAMETER", "id and interface are required")
		return
	}

	created, err := h.queries.CreateNetwork(r.Context(), db.CreateNetworkParams{
		ID:          body.ID,
		Enabled:     body.Enabled,
		InterfaceID: body.Interface,
		Type:        body.Type,
		VlanID:      body.VLANID,
		Subnet:      body.Subnet,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "ERR_DUPLICATE", "network already exists")
		return
	}
	writeJSON(w, http.StatusOK, networkToJSON(created))
}

func (h *Handler) putNetwork(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body networkJSON
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "ERR_INVALID_BODY", err.Error())
		return
	}

	updated, err := h.queries.UpdateNetwork(r.Context(), db.UpdateNetworkParams{
		ID:          id,
		Enabled:     body.Enabled,
		InterfaceID: body.Interface,
		Type:        body.Type,
		VlanID:      body.VLANID,
		Subnet:      body.Subnet,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "network not found")
		return
	}
	writeJSON(w, http.StatusOK, networkToJSON(updated))
}

func (h *Handler) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	if err := h.queries.DeleteNetwork(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "network not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}
