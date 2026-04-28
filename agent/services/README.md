# Agent services — log-tailing observers

The agent does not emulate honeypot services. Instead it tails the log files
written by the *real* daemons running inside the pot image (sshd, vsftpd,
apache2, samba, mysqld, postgres, xrdp). Each tailer parses known patterns
out of its log file and emits structured events to the controller over the
virtio-serial channel.

The motivation is fingerprint resistance: every published "honeypot
emulator" study (Vetterl & Clayton 2018, Srinivasa et al. 2023, Williams
et al. 2024) starts by enumerating the small set of behavioural quirks
that distinguish an emulator from the real software. A real Ubuntu sshd is
indistinguishable from a real Ubuntu sshd because it *is* one. The cost is
that the pot image must ship the real daemons preinstalled and configured
to log auth and access events.

## Supported services

| `type`      | Default log path                              | Default port | Ubuntu package           |
| ----------- | --------------------------------------------- | ------------ | ------------------------ |
| `ssh`       | `/var/log/auth.log`                           | 22           | `openssh-server`         |
| `ftp`       | `/var/log/vsftpd.log`                         | 21           | `vsftpd`                 |
| `http`      | `/var/log/apache2/access.log`                 | 80           | `apache2` (or `nginx`)   |
| `smb`       | `/var/log/samba/log.smbd`                     | 445          | `samba`                  |
| `telnet`    | `/var/log/auth.log`                           | 23           | `telnetd` + `inetutils-inetd` |
| `mysql`     | `/var/log/mysql/error.log`                    | 3306         | `mysql-server` / `mariadb-server` |
| `postgres`  | `/var/log/postgresql/postgresql-*-main.log`   | 5432         | `postgresql`             |
| `rdp`       | `/var/log/xrdp.log`                           | 3389         | `xrdp`                   |

The PostgreSQL path is resolved by glob at agent start so it covers the
`postgresql-16-main.log` / `postgresql-17-main.log` / ... naming used by
the Ubuntu packages. Override `path` on a `ServiceSpec` to point at a
custom location (e.g. an nginx instance writing to a non-default file).

## Patterns matched

`parsers.go` is the source of truth — the table below summarises the
recognised lines and the events produced. Lines that don't match any
pattern are dropped silently.

### `ssh` (sshd)

| Log pattern                                           | Kind         | Data fields                                |
| ----------------------------------------------------- | ------------ | ------------------------------------------ |
| `Failed password\|publickey for [invalid user] X from Y port Z` | `auth`       | `user`, `method`, `result=fail`, optional `valid_user=no` |
| `Accepted password\|publickey for X from Y port Z`     | `auth`       | `user`, `method`, `result=success`         |
| `Invalid user X from Y port Z`                        | `auth`       | `user`, `result=invalid_user`              |
| `Connection from Y port Z`                            | `connection` | —                                          |
| `Disconnected from [authenticating user X] Y port Z`  | `disconnect` | —                                          |

### `ftp` (vsftpd)

| Log pattern                                  | Kind         | Data fields                                |
| -------------------------------------------- | ------------ | ------------------------------------------ |
| `[user] OK\|FAIL LOGIN: Client "<ip>"`        | `auth`       | `user`, `result=success\|fail`              |
| `[user] OK DOWNLOAD\|UPLOAD\|DELETE\|MKDIR\|RMDIR\|RENAME: Client "<ip>", "<path>"` | `command` | `user`, `action`, `path` |
| `CONNECT: Client "<ip>"`                     | `connection` | —                                          |

### `http` (Apache / nginx, NCSA combined log)

Standard combined log line (`%h %l %u %t \"%r\" %>s %b "%{Referer}i" "%{User-Agent}i"`)
yields a `connection` event with `method`, `path`, `proto`, `status`, `size`,
optional `referer`, `user_agent`, `user`. SIEM consumers filter on the
`status` field to surface 401/403/404/500 patterns characteristic of
exploitation traffic.

### `smb` (Samba auth_audit)

Requires `log level = auth_audit:3` (or higher) in `smb.conf` so the
broker emits `Auth: ...` lines. The parser extracts user, NT_STATUS,
and `remote host [ipv4:<ip>:<port>]`. `NT_STATUS_OK` → `result=success`;
anything else → `result=fail` with the raw status preserved.

### `telnet` (telnetd + PAM `login`)

`telnetd` connection events come from syslog (`telnetd[pid]: connect from <ip>`);
PAM authentication failures come from `/var/log/auth.log`
(`login[pid]: FAILED LOGIN ... FOR '<user>', Authentication failure`).
`auth.log` is the default log path so both stream into the same parser.

### `mysql` (MySQL / MariaDB)

`Access denied for user '<user>'@'<host>' (using password: YES\|NO)` →
`auth` event with `user`, `result=fail`, `password_supplied`. Successful
auths are not emitted by default — enable the audit plugin
(`mariadb-plugin-audit` / Percona) and adjust the parser if needed.

### `postgres`

| Log pattern                                                  | Kind         | Data fields                       |
| ------------------------------------------------------------ | ------------ | --------------------------------- |
| `connection received: host=<ip> port=<port>`                 | `connection` | `port`, `pid`                     |
| `connection authorized: user=<user> database=<db>`           | `auth`       | `user`, `database`, `result=success`, `pid` |
| `password authentication failed for user "<user>"`           | `auth`       | `user`, `result=fail`, `pid`      |

The auth lines do not carry the source IP (PostgreSQL writes it on the
preceding `connection received` line). The `pid` field is included so
SIEM consumers can correlate the auth result back to the source IP via
the connection event with the same pid.

Set `log_connections = on` and `log_disconnections = on` in
`postgresql.conf` for the connection events to be emitted.

### `rdp` (xrdp)

| Log pattern                                                | Kind         | Data fields                       |
| ---------------------------------------------------------- | ------------ | --------------------------------- |
| `connection received from <ip> port <port>`                | `connection` | `port`                            |
| `created session (display N): username <user>, ip <ip>:<port>` | `auth`   | `user`, `result=success`          |
| `login failed for user <user>`                             | `auth`       | `user`, `result=fail`             |

## Adding a new service

1. Add a `ServiceType` constant to `agent/config/config.go` and include it
   in `ParseConfig`'s switch.
2. Write a `parseFoo(svcName string) Parser` in `parsers.go`. Match only
   the patterns you care about — non-matches drop silently.
3. Register the type in `serviceDefs` in `registry.go` with its default
   Ubuntu log path and (optionally) a `fallbackGlob`.
4. Map the relevant Ubuntu package name(s) to a `featureService` entry in
   `controller/potmgr/conn.go` so deployments referencing those features
   automatically activate the service.

## Operational requirements inside the pot image

- The agent must be able to read the log files. On a default Ubuntu install
  most are mode `0640 root:adm`. Either run the agent as root (the systemd
  unit in the project README does, by default) or add the agent's user to
  the `adm` group.
- The observed daemon must actually be running. The agent waits indefinitely
  for the log file to appear, so a daemon that fails to start manifests as
  silence in the event stream rather than a crash.
- For services whose default Ubuntu config does not log every interaction
  (Samba, MySQL, PostgreSQL), bake the required log-level configuration into
  the base image. Specifically:
  - Samba: `log level = auth_audit:3` in `[global]`
  - MySQL/MariaDB: default error log already records auth failures
  - PostgreSQL: `log_connections = on`, `log_disconnections = on` in
    `postgresql.conf`
- Per-pot admin credentials delivered by the controller (`AdminUser` /
  `AdminPass`) need a small per-image hook to set the matching account's
  password before the daemon starts accepting connections — typically a
  `chpasswd` invocation in a one-shot systemd unit ordered before the
  observed daemons. Without this, attackers brute-forcing the pot will
  see only `result=fail` events.
