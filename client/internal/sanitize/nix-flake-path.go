package sanitize

import (
	"fmt"
	"path/filepath"
)

func NixFlakeDirFromPath(nixFlakePath string) (string, error) {
	if nixFlakePath == "" {
		return "", fmt.Errorf("nix flake path cannot be empty")
	}

	if !fileExists(nixFlakePath) {
		return "", fmt.Errorf("nix flake path does not exist: %s", nixFlakePath)
	}

	if filepath.Base(nixFlakePath) != "flake.nix" {
		return "", fmt.Errorf("nix flake path must point to a 'flake.nix' file")
	}

	absPath, err := filepath.Abs(nixFlakePath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path of nix flake: %v", err)
	}

	return filepath.Dir(absPath), nil
}
