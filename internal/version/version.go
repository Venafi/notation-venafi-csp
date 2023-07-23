package version

const (
	PluginName   = "venafi-csp"
	SigningAgent = "notation-venafi-csp"
)

var (
	// Version shows the current notation-venafi-csp version, optionally with pre-release.
	Version = "0.2.0"

	// BuildMetadata stores the build metadata.
	BuildMetadata = "release"
)

// GetVersion returns the version string in SemVer 2.
func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "-" + BuildMetadata
}
