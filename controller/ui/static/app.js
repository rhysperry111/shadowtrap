// ShadowTrap admin UI — vanilla JS, no build step.
// The API key is kept in localStorage and sent on every request as the
// api_key header.

const state = {
  key: localStorage.getItem("shadowtrap.key") || "",
};

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (state.key) {
    headers["api_key"] = state.key;
  }
  if (opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch("/api" + path, { ...opts, headers });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;

  if (!res.ok) {
    throw new Error((body && (body.info || body.type)) || res.statusText);
  }
  return body;
}

// Routing.

function showRoute(hash) {
  const name = hash.replace("#", "") || "dashboard";

  $$("section").forEach(s => {
    s.hidden = s.id !== name;
  });
  $$("nav a").forEach(a => {
    a.classList.toggle("active", a.hash === "#" + name);
  });

  const loaders = {
    dashboard:   loadPots,
    deployments: () => Promise.all([loadDeployments(), loadImages()]),
    images:      loadImages,
    networks:    loadNetworks,
    keys:        loadKeys,
  };
  const loader = loaders[name];
  if (loader) {
    loader().catch(showError);
  }
}

window.addEventListener("hashchange", () => showRoute(location.hash));

function showError(err) {
  $("#api-status").textContent = "error: " + err.message;
  $("#api-status").style.color = "var(--danger)";
}

function showStatus(msg) {
  $("#api-status").textContent = msg;
  $("#api-status").style.color = "var(--muted)";
}

// Auth.

$("#api-key").value = state.key;
$("#api-key-save").addEventListener("click", () => {
  state.key = $("#api-key").value.trim();
  localStorage.setItem("shadowtrap.key", state.key);
  showStatus("key saved");
  showRoute(location.hash);
});

// Dashboard (pots).

async function loadPots() {
  const body = await api("/info/pots");
  const tbody = $("#pots-table tbody");
  tbody.innerHTML = "";

  for (const p of body.pots || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${p.id}</td>
      <td>${p.deployment}</td>
      <td>${p.ip || ""}</td>
      <td class="${p.status}">${p.status}</td>
      <td>${p.cred_hint || ""}</td>
      <td>${p.expires_at || "–"}</td>`;
    tbody.appendChild(tr);
  }
  showStatus(`loaded ${body.pots?.length ?? 0} pots`);
}

setInterval(() => {
  if (document.hidden) return;
  if (location.hash.replace("#", "") !== "dashboard") return;
  loadPots().catch(showError);
}, 10000);

// Deployments.

async function loadDeployments() {
  const body = await api("/settings/pots/deployments");
  const tbody = $("#deployments-table tbody");
  tbody.innerHTML = "";

  for (const d of body.deployments || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${d.id}</td>
      <td>${d.active}</td>
      <td>${d.count}</td>
      <td>${(d.image || []).map(i => i.id).join(", ")}</td>
      <td>${(d.network || []).map(n => n.id).join(", ")}</td>
      <td>${d.ipam || "sweep"}</td>
      <td>${d.ttl_minutes || 0}</td>
      <td><button class="delete">delete</button></td>`;

    tr.querySelector("button.delete").addEventListener("click", async () => {
      if (!confirm("Delete deployment " + d.id + "?")) return;
      await api("/settings/pots/deployments/" + d.id, { method: "DELETE" });
      loadDeployments();
    });

    tbody.appendChild(tr);
  }
}

$("#deployment-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const fd = new FormData(e.target);
  const body = {
    id:           fd.get("id"),
    active:       !!fd.get("active"),
    count:        parseInt(fd.get("count"), 10),
    image:        fd.get("image_ids").split(",").map(s => s.trim()).filter(Boolean).map(id => ({id})),
    network:      fd.get("network_ids").split(",").map(s => s.trim()).filter(Boolean).map(id => ({id})),
    ipam:         fd.get("ipam"),
    ttl_minutes:  parseInt(fd.get("ttl_minutes"), 10) || 0,
  };

  // Try POST; if the deployment already exists, fall back to PUT.
  try {
    await api("/settings/pots/deployments", {
      method: "POST",
      body: JSON.stringify(body),
    });
  } catch (err) {
    if (!err.message.includes("exists")) throw err;
    await api("/settings/pots/deployments/" + body.id, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  }

  e.target.reset();
  loadDeployments();
});

// Images.

async function loadImages() {
  const body = await api("/settings/pots/images");
  const tbody = $("#images-table tbody");
  tbody.innerHTML = "";

  for (const img of body.images || []) {
    const features = (img.features || []).map(f => `${f.name} ${f.version}`).join(", ");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${img.id}</td>
      <td>${img.base}</td>
      <td>${img.version}</td>
      <td>${img.os}</td>
      <td>${features}</td>`;
    tbody.appendChild(tr);
  }
}

// Networks.

async function loadNetworks() {
  // Host config.
  const host = await api("/settings/network/host").catch(() => ({mode: "dhcp"}));
  const f = $("#host-form");
  f.network.value        = host.network        || "";
  f.mode.value           = host.mode           || "dhcp";
  f.static_ip.value      = host.static_ip      || "";
  f.static_gateway.value = host.static_gateway || "";
  f.static_dns.value     = host.static_dns     || "";

  // Interfaces.
  const ifaces = await api("/settings/network/interfaces");
  const ibody = $("#interfaces-table tbody");
  ibody.innerHTML = "";
  for (const i of ifaces.interfaces || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${i.id}</td><td>${i.enabled}</td><td>${i.link}</td><td>${i.mode || ""}</td>`;
    ibody.appendChild(tr);
  }

  // Networks.
  const nets = await api("/settings/network/networks");
  const nbody = $("#networks-table tbody");
  nbody.innerHTML = "";
  for (const n of nets.networks || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${n.id}</td>
      <td>${n.enabled}</td>
      <td>${n.interface}</td>
      <td>${n.type || "native"}</td>
      <td>${n.vlan_id || 0}</td>
      <td>${n.subnet || ""}</td>
      <td><button class="delete">delete</button></td>`;

    tr.querySelector("button.delete").addEventListener("click", async () => {
      if (!confirm("Delete network " + n.id + "?")) return;
      await api("/settings/network/networks/" + n.id, { method: "DELETE" });
      loadNetworks();
    });

    nbody.appendChild(tr);
  }
}

$("#host-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await api("/settings/network/host", {
    method: "PUT",
    body: JSON.stringify({
      network:        fd.get("network"),
      mode:           fd.get("mode"),
      static_ip:      fd.get("static_ip"),
      static_gateway: fd.get("static_gateway"),
      static_dns:     fd.get("static_dns"),
    }),
  });
  loadNetworks();
});

$("#network-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const fd = new FormData(e.target);
  const body = {
    id:        fd.get("id"),
    enabled:   !!fd.get("enabled"),
    interface: fd.get("interface"),
    type:      fd.get("type"),
    vlan_id:   parseInt(fd.get("vlan_id"), 10) || 0,
    subnet:    fd.get("subnet"),
  };

  try {
    await api("/settings/network/networks", {
      method: "POST",
      body: JSON.stringify(body),
    });
  } catch (err) {
    if (!err.message.includes("exists")) throw err;
    await api("/settings/network/networks/" + body.id, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  }

  e.target.reset();
  loadNetworks();
});

// API keys.

async function loadKeys() {
  const body = await api("/settings/auth/keys");
  const tbody = $("#keys-table tbody");
  tbody.innerHTML = "";

  for (const k of body.keys || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${k.name}</td>
      <td>${k.role}</td>
      <td>${k.created_at}</td>
      <td><button class="delete">delete</button></td>`;

    tr.querySelector("button.delete").addEventListener("click", async () => {
      if (!confirm("Delete key " + k.name + "?")) return;
      await api("/settings/auth/keys/" + k.name, { method: "DELETE" });
      loadKeys();
    });

    tbody.appendChild(tr);
  }
}

$("#key-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const fd = new FormData(e.target);
  const body = await api("/settings/auth/keys", {
    method: "POST",
    body: JSON.stringify({
      name: fd.get("name"),
      role: fd.get("role"),
    }),
  });

  // The raw key is shown only this once.
  const out = $("#key-output");
  out.hidden = false;
  out.textContent =
    `Save this key now — it is shown only once:\n\n` +
    `name: ${body.name}\nrole: ${body.role}\nkey:  ${body.key}\n`;

  e.target.reset();
  loadKeys();
});

// Initial render.

showRoute(location.hash);
