package managementasset

import "embed"

//go:embed static/management.html
var embeddedFS embed.FS

// EmbeddedManagementHTML returns the bundled management panel HTML.
// This serves as a built-in fallback when the local file does not exist
// and the remote GitHub download is unavailable.
func EmbeddedManagementHTML() ([]byte, error) {
	return embeddedFS.ReadFile("static/management.html")
}
