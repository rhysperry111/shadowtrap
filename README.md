# ShadowTrap

> [!WARNING]
>
> When I started this project I had never touched go before, and so a large part
> of the codebase has currently been written with the heavy help of AI autocomplete. While I've read it
> all, and understand what it's doing, the entire project will likely undergo a huge
> rework in the future now that I have an understanding of the needed architecture
> and go's development patterns.
>
> That'll likely come about once I've finished my degree and have some more spare time,
> but it'd feel disingenuous not to mention it.

ShadowTrap is a service to automatically deploy honeypots across a
network. It places pots on unused IP addresses either synced from an
external IPAM or discovered by sweep, runs each pot as a short-lived
KVM guest behind a kernel-enforced fail-closed network filter, and
forwards structured threat telemetry to external consumers.

The project is split into two Go modules:

- `controller/` — the central control plane (HTTP API, web UI, libvirt
  driver, PostgreSQL persistence, pot scheduler).
- `agent/` — the in-guest agent that receives config over virtio-serial
  and drives emulated services.

This README covers what you need to run the controller on a single
Linux host. Anything prefixed with `#` is run as root.

## Prerequisites

All development has been against Arch Linux; any recent Linux host with
KVM and libvirt will work.

- **Linux** kernel 5.15+ with KVM support (`kvm-intel` or `kvm-amd`).
- **libvirt** 9.0+ and **QEMU/KVM** — provides the socket at
  `/var/run/libvirt/libvirt-sock` that the controller talks to.
- **qemu-img** — used at image-prep time to create the qcow2 base
  images.
- **nftables** — the controller installs a bridge-family table
  (`shadowtrap`) at startup as the host-side stateful backstop on top
  of the per-NIC libvirt nwfilter. The `nft` binary must be on `PATH`.
- **PostgreSQL** 14+ — a single database for controller state.
- **Go** 1.22+ — to build the controller and agent binaries.

On Arch:

```sh
# pacman -S libvirt qemu-full dnsmasq postgresql nftables go
# systemctl enable --now libvirtd.socket
# systemctl enable --now postgresql
```

The controller needs `CAP_NET_ADMIN` (to manage bridges and install the
nftables backstop) and `CAP_SYSLOG` (to read `/dev/kmsg` for host-firewall
drop attribution). Running as `root` is the simplest path; otherwise:

```sh
# setcap cap_net_admin,cap_syslog+ep /usr/local/bin/shadowtrap-controller
# usermod -aG libvirt $USER
```

## Building

```sh
cd shadowtrap/controller && go build -o shadowtrap-controller
cd shadowtrap/agent      && go build -o shadowtrap-agent
```

The controller is a single static binary. The UI is embedded via
`//go:embed`, so there is nothing else to deploy.

## Database setup

Create a database and apply the schema:

```sh
$ createdb shadowtrap
$ psql -d shadowtrap -f controller/db/schema.sql
```

Any libpq-style DSN works; export it as `SHADOWTRAP_DB_DSN` or pass it
via `--db`:

```sh
export SHADOWTRAP_DB_DSN='postgres://shadowtrap@/shadowtrap?sslmode=disable'
```

## Base images

The controller expects qcow2 base images in `--images-dir` (default
`/var/lib/shadowtrap/images`), with a matching row in the `images`
table describing the base OS and emulated services.

Minimum working example — an Ubuntu cloud image with a Cowrie-style SSH
emulator baked into the agent. (Debian 12's `genericcloud` image ships
with a broken cloud-init at the time of writing, so Ubuntu is the
known-good default.)

```sh
# mkdir -p /var/lib/shadowtrap/images
# curl -o /var/lib/shadowtrap/images/ubuntu-24.04.qcow2 \
       https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
```

Register it in the database:

```sql
INSERT INTO images (id, base, version, os, features) VALUES
  ('ubuntu-24.04-ssh', 'ubuntu-24.04.qcow2', '24.04', 'linux',
   '[{"name":"ssh","version":"1"}]');
```

Build the agent (`shadowtrap-agent`) into the image and install a
systemd unit that runs it against `/dev/vport0p0`. An example unit:

```ini
[Unit]
Description=ShadowTrap agent
After=network.target

[Service]
ExecStart=/usr/local/bin/shadowtrap-agent
Restart=always

[Install]
WantedBy=multi-user.target
```

The controller adds a virtio-serial channel to every pot it launches;
no configuration is needed inside the guest beyond enabling this unit.

## Running the controller

A minimal first-run:

```sh
export SHADOWTRAP_DB_DSN='postgres://shadowtrap@/shadowtrap?sslmode=disable'
export SHADOWTRAP_API_KEY="$(openssl rand -hex 32)"

./shadowtrap-controller \
    --addr       :8080 \
    --images-dir /var/lib/shadowtrap/images \
    --run-dir    /run/shadowtrap \
    --libvirt    /var/run/libvirt/libvirt-sock \
    --interval   30s
```

Flags:

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--addr` | — | `:8080` | HTTP listen address for API + UI |
| `--db` | `SHADOWTRAP_DB_DSN` | — | PostgreSQL DSN (required) |
| `--api-key` | `SHADOWTRAP_API_KEY` | — | admin master key (required on first boot) |
| `--images-dir` | — | `/var/lib/shadowtrap/images` | base qcow2 location |
| `--run-dir` | — | `/run/shadowtrap` | runtime state for pot sockets |
| `--libvirt` | — | `/var/run/libvirt/libvirt-sock` | libvirt UNIX socket |
| `--interval` | — | `30s` | scheduler reconcile cadence |

On startup the controller:

1. Opens two libvirt connections (domain + network driver).
2. Loads `br_netfilter` / `nf_conntrack` / `nf_conntrack_bridge` and
   installs the `bridge shadowtrap` nftables table. This is the host-
   side stateful backstop: any pot-originated frame (identified by the
   `02:73:74:**:**:**` MAC OUI) that is not part of an inbound-initiated
   conntrack flow is logged with a `shadowtrap-drop:` prefix, counted
   in `pot_egress_drops`, and dropped. If `nft` is missing or the
   ruleset will not load the controller refuses to start.
3. Installs the `shadowtrap-pot` libvirt nwfilter — the primary,
   per-NIC stateful filter (default-deny egress, anti-MAC-spoofing,
   anti-ARP-spoofing, drop-all-IPv6). Same fail-closed posture.
4. Scans host interfaces and seeds the `interfaces` table.
5. Reconnects to any pots that survived a restart.
6. Starts the scheduler (reconcile + TTL reaper loop), the containment
   watchdog (samples per-pot interface counters every 5 s), and the
   drop watcher (tails `/dev/kmsg` for `shadowtrap-drop:` lines, maps
   the source MAC back to a pot, and rebuilds it).
7. Serves the API under `/api/` and the admin UI at `/`.

### systemd unit

For persistent operation, drop this in
`/etc/systemd/system/shadowtrap-controller.service`:

```ini
[Unit]
Description=ShadowTrap controller
After=network.target libvirtd.service postgresql.service
Wants=libvirtd.service postgresql.service

[Service]
Type=simple
User=shadowtrap
Group=libvirt
EnvironmentFile=/etc/shadowtrap/controller.env
ExecStart=/usr/local/bin/shadowtrap-controller --addr :8080
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

With `/etc/shadowtrap/controller.env` holding `SHADOWTRAP_DB_DSN` and
`SHADOWTRAP_API_KEY`. Mode `0600`, owner `shadowtrap`.

## Using the web UI

Open `http://<host>:8080/`. Paste the master API key into the header
input and click **Use** — it is stored in `localStorage` and sent as
the `api_key` header on every API call.

Tabs:

- **Dashboard** — live list of pots (auto-refresh every 10s) showing
  status, IP, credential hint, and TTL expiry.
- **Deployments** — create, edit, and delete deployments. A
  deployment pins an image set, a network set, an IPAM source
  (`sweep` / `phpipam` / `netbox`), a target pot count, and an
  optional per-pot TTL.
- **Images** — view registered base images and their features.
- **Networks** — host-facing network configuration (mode, static
  addressing), the host interface inventory, and the configured VLANs
  / native networks used by deployments.
- **API keys** — manage additional keys. Each key has a role
  (`viewer`, `operator`, `admin`); the raw key is shown **once** at
  creation time and is not recoverable afterwards.

The master key (`--api-key`) always has admin scope. In production
you should create a named admin key via the UI and rotate the master
key out of the environment.

## Operational notes

- **Fail-closed is non-negotiable.** If the nwfilter fails to install,
  or libvirt is unreachable, the controller exits. Do not patch this
  out — uncontained honeypots are an ethics and legal problem, not an
  inconvenience.
- **TTL-reaped pots lose state.** Set `ttl_minutes = 0` if you want
  long-lived pots; any interaction telemetry is forwarded before the
  reap regardless.
- **Credentials are shown only once.** The controller stores a
  fingerprint hint (`user@host` truncated) for display, never the
  full credential.
- **Images are read-only to pots.** Each pot boots from a qcow2
  overlay; the base image is never mutated.

## Troubleshooting

- `libvirt domain socket: permission denied` — check the
  `libvirt` group membership; log out and back in.
- `libvirt start: Cannot access storage file ... Permission denied (as uid:956 ...)` —
  QEMU runs as a separate user (`qemu`) and cannot traverse
  `$XDG_RUNTIME_DIR` (mode 0700). Point `--run-dir` at a shared path
  whose group is one libvirt's QEMU process can read:
  ```sh
  # mkdir -p /var/lib/shadowtrap/run
  # chown $USER:libvirt /var/lib/shadowtrap/run
  # chmod 0770 /var/lib/shadowtrap/run
  ```
  ShadowTrap inherits the parent directory's gid onto every pot
  directory (mode 2770) and the cloned disk image (mode 0660), so
  whatever group you set above is the group that gets read/write
  access to all pot artefacts. Alternatively, make libvirt's QEMU run
  as your own user by adding `user = "<you>"` and `group = "<you>"`
  to `/etc/libvirt/qemu.conf` and restarting `libvirtd`. The
  controller refuses to start with a `--run-dir` under `/run/user/`
  for this reason.
- `scheduler bootstrap: ... NwfilterDefineXML` — libvirt is too old
  or nwfilter is compiled out. Upgrade libvirt.
- `http: listen tcp :8080: bind: permission denied` — pick a port
  above 1024 or grant `CAP_NET_BIND_SERVICE` to the binary.
- UI loads but API calls 401 — the `api_key` header is missing or
  the key has been deleted. Re-paste it.
