package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"shadowtrap/controller/db"
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type Permission string

const (
	PermRead  Permission = "read"
	PermWrite Permission = "write"
	PermAdmin Permission = "admin"
)

var rolePerms = map[Role]map[Permission]bool{
	RoleViewer:   {PermRead: true},
	RoleOperator: {PermRead: true, PermWrite: true},
	RoleAdmin:    {PermRead: true, PermWrite: true, PermAdmin: true},
}

func roleHasPerm(role Role, perm Permission) bool {
	return rolePerms[role][perm]
}

// authenticate resolves the api_key header to a Role. The in-memory
// master key is always admin and is never persisted; it exists for
// bootstrapping and key management.
func (h *Handler) authenticate(r *http.Request) (Role, bool) {
	key := r.Header.Get("api_key")
	if key == "" {
		return "", false
	}
	if h.masterKey != "" && key == h.masterKey {
		return RoleAdmin, true
	}

	apiKey, err := h.queries.GetAPIKey(r.Context(), HashKey(key))
	if err != nil {
		return "", false
	}

	role := Role(apiKey.Role)
	if _, valid := rolePerms[role]; !valid {
		return "", false
	}
	return role, true
}

// require returns middleware that gates the wrapped handler on perm.
func (h *Handler) require(perm Permission) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			role, ok := h.authenticate(r)
			if !ok {
				writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "invalid or missing api_key")
				return
			}
			if !roleHasPerm(role, perm) {
				writeError(w, http.StatusForbidden, "ERR_FORBIDDEN", "insufficient permissions")
				return
			}
			next(w, r)
		}
	}
}

// HashKey returns the hex-encoded SHA-256 of a raw API key.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// GenerateKey makes a random 32-byte hex key and its hash.
func GenerateKey() (key, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return
	}
	key = hex.EncodeToString(buf)
	hash = HashKey(key)
	return
}

func ValidRole(name string) bool {
	_, ok := rolePerms[Role(name)]
	return ok
}

func ValidRoles() []string {
	return []string{string(RoleViewer), string(RoleOperator), string(RoleAdmin)}
}

// apiKeyInfo is the outbound representation of a db.APIKey. The hash
// is never sent — only name, role, and creation time.
type apiKeyInfo struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

func apiKeyToInfo(key db.APIKey) apiKeyInfo {
	return apiKeyInfo{
		Name:      key.Name,
		Role:      key.Role,
		CreatedAt: key.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}
