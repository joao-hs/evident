package domain

const CurrentManifestVersion = "1.0.0"

type Manifest struct {
	Version string         `json:"version"`
	Source  ManifestSource `json:"source"`
	Build   ManifestBuild  `json:"build"`
	Image   ManifestImage  `json:"image"`
}

type ManifestSource struct {
	GitRepo   string `json:"git-repo"`
	GitCommit string `json:"git-commit"`
}

type ManifestBuild struct {
	NixVersion string `json:"nix-version"`
	Package    string `json:"package"`
}

type ManifestImage struct {
	Digest    string `json:"digest"`
	SizeBytes int    `json:"size-bytes"`
}
