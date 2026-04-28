package services

import (
	"regexp"
	"strings"
	"time"

	"shadowtrap/agent/events"
)

// Parser turns a single log line into an Event. ok is false when the line
// doesn't match anything we care about — non-matching lines are dropped.
//
// Parsers run on every line of every log we tail, so they should stay
// cheap (one or two regex matches) and avoid per-line allocations where
// possible.
type Parser func(line string) (events.Event, bool)

func now() time.Time { return time.Now().UTC() }

// SSH (sshd, /var/log/auth.log on Debian/Ubuntu).

var (
	sshFailed   = regexp.MustCompile(`Failed (password|publickey) for (invalid user )?(\S+) from (\S+) port (\d+)`)
	sshAccepted = regexp.MustCompile(`Accepted (password|publickey) for (\S+) from (\S+) port (\d+)`)
	sshInvalid  = regexp.MustCompile(`Invalid user (\S+) from (\S+) port (\d+)`)
	sshConnect  = regexp.MustCompile(`Connection from (\S+) port (\d+)`)
	sshDisconn  = regexp.MustCompile(`Disconnected from (?:authenticating user \S+ )?(\S+) port (\d+)`)
)

func parseSSH(svc string) Parser {
	return func(line string) (events.Event, bool) {
		// auth.log also carries sudo, login, cron, and the telnet parser
		// reads the same file. Filter to sshd lines only.
		if !strings.Contains(line, "sshd[") {
			return events.Event{}, false
		}

		if m := sshFailed.FindStringSubmatch(line); m != nil {
			data := map[string]string{
				"user":   m[3],
				"method": m[1],
				"result": "fail",
			}
			if m[2] != "" {
				data["valid_user"] = "no"
			}
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Source:  m[4],
				Data:    data,
			}, true
		}

		if m := sshAccepted.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Source:  m[3],
				Data: map[string]string{
					"user":   m[2],
					"method": m[1],
					"result": "success",
				},
			}, true
		}

		if m := sshInvalid.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Source:  m[2],
				Data: map[string]string{
					"user":   m[1],
					"result": "invalid_user",
				},
			}, true
		}

		if m := sshConnect.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindConnection,
				Source:  m[1],
			}, true
		}

		if m := sshDisconn.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindDisconnect,
				Source:  m[1],
			}, true
		}

		return events.Event{}, false
	}
}

// FTP (vsftpd, /var/log/vsftpd.log).

var (
	vsftpdConnect = regexp.MustCompile(`CONNECT: Client "(\S+)"`)
	vsftpdLogin   = regexp.MustCompile(`\[(\S+)\] (OK|FAIL) LOGIN: Client "(\S+)"`)
	vsftpdAction  = regexp.MustCompile(`\[(\S+)\] OK (DOWNLOAD|UPLOAD|DELETE|MKDIR|RMDIR|RENAME): Client "(\S+)", "([^"]+)"`)
)

func parseVsftpd(svc string) Parser {
	return func(line string) (events.Event, bool) {
		if m := vsftpdLogin.FindStringSubmatch(line); m != nil {
			result := "fail"
			if m[2] == "OK" {
				result = "success"
			}
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Source:  m[3],
				Data: map[string]string{
					"user":   m[1],
					"result": result,
				},
			}, true
		}

		if m := vsftpdAction.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindCommand,
				Source:  m[3],
				Data: map[string]string{
					"user":   m[1],
					"action": strings.ToLower(m[2]),
					"path":   m[4],
				},
			}, true
		}

		if m := vsftpdConnect.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindConnection,
				Source:  m[1],
			}, true
		}

		return events.Event{}, false
	}
}

// HTTP — Apache combined log; nginx defaults to a compatible format.
// Combined fields: <ip> <ident> <user> [<time>] "<method> <path> <proto>"
//                  <status> <size> "<referer>" "<ua>"

var httpCombined = regexp.MustCompile(
	`^(\S+) \S+ (\S+) \[[^\]]+\] "([A-Z]+) (\S+) (HTTP/[\d.]+)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?`)

func parseHTTP(svc string) Parser {
	return func(line string) (events.Event, bool) {
		m := httpCombined.FindStringSubmatch(line)
		if m == nil {
			return events.Event{}, false
		}

		data := map[string]string{
			"method": m[3],
			"path":   m[4],
			"proto":  m[5],
			"status": m[6],
			"size":   m[7],
		}
		if m[2] != "-" {
			data["user"] = m[2]
		}
		if len(m) >= 9 && m[8] != "" && m[8] != "-" {
			data["referer"] = m[8]
		}
		if len(m) >= 10 && m[9] != "" && m[9] != "-" {
			data["user_agent"] = m[9]
		}

		return events.Event{
			Time:    now(),
			Service: svc,
			Kind:    events.KindConnection,
			Source:  m[1],
			Data:    data,
		}, true
	}
}

// SMB — Samba auth_audit lines from /var/log/samba/log.smbd.
// Samba 4 emits these once "log level" includes "auth_audit:3+".

var smbAuth = regexp.MustCompile(
	`Auth:.*user \[[^\]]*\]\\\[([^\]]+)\].*status \[(NT_STATUS_\w+)\].*remote host \[ipv[46]:([^\]:]+)`)

func parseSMB(svc string) Parser {
	return func(line string) (events.Event, bool) {
		m := smbAuth.FindStringSubmatch(line)
		if m == nil {
			return events.Event{}, false
		}

		result := "fail"
		if m[2] == "NT_STATUS_OK" {
			result = "success"
		}

		return events.Event{
			Time:    now(),
			Service: svc,
			Kind:    events.KindAuth,
			Source:  m[3],
			Data: map[string]string{
				"user":   m[1],
				"result": result,
				"status": m[2],
			},
		}, true
	}
}

// Telnet — telnetd syslog plus PAM login failures from auth.log.

var (
	telnetConnect = regexp.MustCompile(`telnetd\[\d+\]: connect from (\S+)`)
	telnetFail    = regexp.MustCompile(`login\[\d+\]: FAILED LOGIN \(\d+\) on '([^']+)' FOR '([^']+)'`)
)

func parseTelnet(svc string) Parser {
	return func(line string) (events.Event, bool) {
		if m := telnetConnect.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindConnection,
				Source:  m[1],
			}, true
		}

		if m := telnetFail.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Data: map[string]string{
					"user":   m[2],
					"tty":    m[1],
					"result": "fail",
				},
			}, true
		}

		return events.Event{}, false
	}
}

// MySQL / MariaDB (/var/log/mysql/error.log).

var mysqlAuthFail = regexp.MustCompile(
	`Access denied for user '([^']+)'@'([^']+)'(?: \(using password: (\w+)\))?`)

func parseMySQL(svc string) Parser {
	return func(line string) (events.Event, bool) {
		m := mysqlAuthFail.FindStringSubmatch(line)
		if m == nil {
			return events.Event{}, false
		}

		data := map[string]string{
			"user":   m[1],
			"result": "fail",
		}
		if len(m) >= 4 && m[3] != "" {
			data["password_supplied"] = strings.ToLower(m[3])
		}

		return events.Event{
			Time:    now(),
			Service: svc,
			Kind:    events.KindAuth,
			Source:  m[2],
			Data:    data,
		}, true
	}
}

// PostgreSQL (/var/log/postgresql/postgresql-XX-main.log).
// On Ubuntu the default log_line_prefix is '%m [%p] %q%u@%d ' once
// log_connections=on; we pull out [pid] for cross-line correlation.

var (
	pgPID      = regexp.MustCompile(`\[(\d+)\]`)
	pgConnect  = regexp.MustCompile(`connection received: host=(\S+) port=(\d+)`)
	pgAuthFail = regexp.MustCompile(`password authentication failed for user "([^"]+)"`)
	pgAuthOK   = regexp.MustCompile(`connection authorized: user=(\S+)\s+database=(\S+)`)
)

func parsePostgres(svc string) Parser {
	return func(line string) (events.Event, bool) {
		pid := ""
		if m := pgPID.FindStringSubmatch(line); m != nil {
			pid = m[1]
		}

		if m := pgConnect.FindStringSubmatch(line); m != nil {
			data := map[string]string{"port": m[2]}
			if pid != "" {
				data["pid"] = pid
			}
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindConnection,
				Source:  m[1],
				Data:    data,
			}, true
		}

		if m := pgAuthFail.FindStringSubmatch(line); m != nil {
			data := map[string]string{
				"user":   m[1],
				"result": "fail",
			}
			if pid != "" {
				data["pid"] = pid
			}
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Data:    data,
			}, true
		}

		if m := pgAuthOK.FindStringSubmatch(line); m != nil {
			data := map[string]string{
				"user":     m[1],
				"database": m[2],
				"result":   "success",
			}
			if pid != "" {
				data["pid"] = pid
			}
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Data:    data,
			}, true
		}

		return events.Event{}, false
	}
}

// RDP — xrdp's two log files (/var/log/xrdp.log and xrdp-sesman.log).

var (
	xrdpConnect = regexp.MustCompile(`connection received from (\S+) port (\d+)`)
	xrdpLoginOK = regexp.MustCompile(`created session \(display \d+\): username (\S+), ip (\S+):\d+`)
	xrdpLoginNo = regexp.MustCompile(`login failed for user (\S+)`)
)

func parseRDP(svc string) Parser {
	return func(line string) (events.Event, bool) {
		if m := xrdpConnect.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindConnection,
				Source:  m[1],
				Data:    map[string]string{"port": m[2]},
			}, true
		}

		if m := xrdpLoginOK.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Source:  m[2],
				Data: map[string]string{
					"user":   m[1],
					"result": "success",
				},
			}, true
		}

		if m := xrdpLoginNo.FindStringSubmatch(line); m != nil {
			return events.Event{
				Time:    now(),
				Service: svc,
				Kind:    events.KindAuth,
				Data: map[string]string{
					"user":   m[1],
					"result": "fail",
				},
			}, true
		}

		return events.Event{}, false
	}
}
