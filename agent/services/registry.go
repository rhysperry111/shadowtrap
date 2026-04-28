package services

import (
	"fmt"

	"shadowtrap/agent/config"
	"shadowtrap/agent/events"
)

// serviceDef pairs a service type with the log we tail for it and the
// parser that turns lines into events.
type serviceDef struct {
	defaultPath string
	parser      func(name string) Parser

	// fallbackGlob covers daemons whose log path includes a moving
	// version number — postgresql, mostly — that a single hard-coded
	// path cannot describe across releases.
	fallbackGlob string
}

var serviceDefs = map[config.ServiceType]serviceDef{
	config.ServiceSSH:    {defaultPath: "/var/log/auth.log", parser: parseSSH},
	config.ServiceFTP:    {defaultPath: "/var/log/vsftpd.log", parser: parseVsftpd},
	config.ServiceHTTP:   {defaultPath: "/var/log/apache2/access.log", parser: parseHTTP},
	config.ServiceSMB:    {defaultPath: "/var/log/samba/log.smbd", parser: parseSMB},
	config.ServiceTelnet: {defaultPath: "/var/log/auth.log", parser: parseTelnet},
	config.ServiceMySQL:  {defaultPath: "/var/log/mysql/error.log", parser: parseMySQL},
	config.ServicePostgres: {
		defaultPath:  "/var/log/postgresql/postgresql.log",
		fallbackGlob: "/var/log/postgresql/postgresql-*-main.log",
		parser:       parsePostgres,
	},
	config.ServiceRDP: {defaultPath: "/var/log/xrdp.log", parser: parseRDP},
}

func newService(spec config.ServiceSpec, streamer *events.Streamer) (Service, error) {
	def, ok := serviceDefs[spec.Type]
	if !ok {
		return nil, fmt.Errorf("unknown service type: %s", spec.Type)
	}

	path := spec.Path
	if path == "" {
		path = def.defaultPath
	}
	if def.fallbackGlob != "" {
		if resolved := resolveGlob(def.fallbackGlob); resolved != "" {
			path = resolved
		}
	}

	name := fmt.Sprintf("%s:%d", spec.Type, spec.Port)
	return newLogService(string(spec.Type), spec.Port, path, def.parser(name), streamer), nil
}
