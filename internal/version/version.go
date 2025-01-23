package version

const (
	PluginName   = "venafi-csp"
	SigningAgent = "notation-venafi-csp"
)

var (
	// Version shows the current notation-venafi-csp version, optionally with pre-release.
	Version                      = "0.3.2"
	VerificationPluginMinVersion = "0.2.0"

	// BuildMetadata stores the build metadata.
	BuildMetadata = ""
)

// GetVersion returns the version string in SemVer 2.
func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "-" + BuildMetadata
}

func GetVerificationPluginMinVersion() string {
	if BuildMetadata == "" {
		return VerificationPluginMinVersion
	}
	return VerificationPluginMinVersion + "-" + BuildMetadata
}
