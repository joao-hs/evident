package sanitize

func ImageVariation(variation string) (string, error) {
	// TODO: nix flake show --quiet --no-pretty --json <flake-path> | jq '.packages."x86_64-linux" | keys[]'

	return variation, nil
}
