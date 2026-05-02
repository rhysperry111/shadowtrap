// Package ui serves the embedded admin web interface.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var files embed.FS

// Handler serves the embedded UI under /.
func Handler() http.Handler {
	sub, _ := fs.Sub(files, "static")
	return http.FileServer(http.FS(sub))
}
