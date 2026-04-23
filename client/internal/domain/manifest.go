package domain

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const CurrentManifestVersion = 1

const (
	_MANIFEST_KEY_VERSION                 = "VERSION"
	_MANIFEST_KEY_NIX_VERSION             = "NIX"
	_MANIFEST_KEY_SOURCE                  = "SOURCE"
	_MANIFEST_KEY_FLAKE_ATTR              = "ATTR"
	_MANIFEST_KEY_DRV                     = "DRV"
	_MANIFEST_KEY_IMAGE_HASH              = "OUT"
	_MANIFEST_KEY_IMAGE_MEASUREMENTS_HASH = "MOUT"
)

var (
	_NIX_VERSION_SEMVER_RE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	// Each segment is either:
	//   - An unquoted identifier: [a-zA-Z_][a-zA-Z0-9_-]*
	//   - A quoted string: "..." (no support for escaping quotes inside)
	_FLAKE_ATTR_RE = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_-]*|"[^"]*")(\.[a-zA-Z_][a-zA-Z0-9_-]*|\.("[^"]*"))*$`)
)

type Manifest struct {
	Version                 int
	NixVersion              string
	SourceUrl               string
	SourceCommit            string
	FlakeAttr               string
	DrvPathHash             string
	DrvOutputName           string
	DrvSha512               string
	ImageSha512             string
	ImageMeasurementsSha512 string
}

func ParseManifest(r io.Reader) (*Manifest, error) {
	m := &Manifest{}
	seen := make(map[string]bool)
	scanner := bufio.NewReader(r)

	for {
		line, err := scanner.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, rest, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("malformed line: %q", line)
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate key: %q", key)
		}
		seen[key] = true

		switch key {
		case _MANIFEST_KEY_VERSION:
			// VERSION <number>
			version, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return nil, fmt.Errorf("invalid VERSION value: %q", rest)
			}
			if version != CurrentManifestVersion {
				return nil, fmt.Errorf("unsupported manifest version: %d", m.Version)
			}
			m.Version = version
		case _MANIFEST_KEY_NIX_VERSION:
			// NIX <nix-version>
			if !_NIX_VERSION_SEMVER_RE.MatchString(rest) {
				return nil, fmt.Errorf("invalid NIX version: %q", rest)
			}
			m.NixVersion = rest
		case _MANIFEST_KEY_SOURCE:
			// SOURCE git+<repo-url>@<commit-hash>
			if !strings.HasPrefix(rest, "git+") {
				return nil, fmt.Errorf("SOURCE must be pinned to a git vsc (missing git+ prefix)")
			}
			if !strings.Contains(rest, "@") {
				return nil, fmt.Errorf("SOURCE must be pinned to a commit (missing @)")
			}

			sourceParts := strings.SplitN(rest[len("git+"):], "@", 2)
			if len(sourceParts) != 2 {
				return nil, fmt.Errorf("invalid SOURCE format: %q", rest)
			}
			m.SourceUrl = sourceParts[0]
			m.SourceCommit = sourceParts[1]

		case _MANIFEST_KEY_FLAKE_ATTR:
			// ATTR <flake-attribute>
			if !_FLAKE_ATTR_RE.MatchString(rest) {
				return nil, fmt.Errorf("invalid flake attribute: %q", rest)
			}
			m.FlakeAttr = rest
		case _MANIFEST_KEY_DRV:
			// DRV <drv-hash>-<output-name>.drv <hash-alg>:<hash-value>
			parts := strings.Fields(rest)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid DRV line: %q", rest)
			}
			drvPart := parts[0]
			hashPart := parts[1]

			drvParts := strings.SplitN(drvPart, "-", 2)
			if len(drvParts) != 2 || !strings.HasSuffix(drvParts[1], ".drv") {
				return nil, fmt.Errorf("invalid DRV path: %q", drvPart)
			}
			m.DrvPathHash = drvParts[0]
			m.DrvOutputName = drvParts[1][:len(drvParts[1])-len(".drv")] // remove .drv suffix

			hashParts := strings.SplitN(hashPart, ":", 2)
			if len(hashParts) != 2 {
				return nil, fmt.Errorf("invalid DRV hash: %q", hashPart)
			}
			switch hashParts[0] {
			case "sha512":
				if len(hashParts[1]) != 128 {
					return nil, fmt.Errorf("invalid sha512 hash length: %d", len(hashParts[1]))
				}
			default:
				return nil, fmt.Errorf("only sha512 hash algorithm is supported, not: %q", hashParts[0])
			}

			m.DrvSha512 = hashParts[1]
		case _MANIFEST_KEY_IMAGE_HASH:
			// OUT sha512:<hash-value>
			hashParts := strings.SplitN(rest, ":", 2)
			if len(hashParts) != 2 {
				return nil, fmt.Errorf("invalid OUT hash: %q", rest)
			}
			switch hashParts[0] {
			case "sha512":
				if len(hashParts[1]) != 128 {
					return nil, fmt.Errorf("invalid sha512 hash length: %d", len(hashParts[1]))
				}
			default:
				return nil, fmt.Errorf("only sha512 hash algorithm is supported, not: %q", hashParts[0])
			}
			m.ImageSha512 = hashParts[1]
		case _MANIFEST_KEY_IMAGE_MEASUREMENTS_HASH:
			// MOUT sha512:<hash-value>
			hashParts := strings.SplitN(rest, ":", 2)
			if len(hashParts) != 2 {
				return nil, fmt.Errorf("invalid MOUT hash: %q", rest)
			}
			switch hashParts[0] {
			case "sha512":
				if len(hashParts[1]) != 128 {
					return nil, fmt.Errorf("invalid sha512 hash length: %d", len(hashParts[1]))
				}
			default:
				return nil, fmt.Errorf("only sha512 hash algorithm is supported, not: %q", hashParts[0])
			}
			m.ImageMeasurementsSha512 = hashParts[1]
		default:
			return nil, fmt.Errorf("unknown manifest key: %q", key)
		}
	}

	if m.Version == 0 {
		return nil, fmt.Errorf("missing %s key", _MANIFEST_KEY_VERSION)
	}

	if m.NixVersion == "" {
		return nil, fmt.Errorf("missing %s key", _MANIFEST_KEY_NIX_VERSION)
	}

	if m.SourceUrl == "" || m.SourceCommit == "" {
		return nil, fmt.Errorf("missing or incomplete %s key", _MANIFEST_KEY_SOURCE)
	}

	if m.FlakeAttr == "" {
		return nil, fmt.Errorf("missing %s key", _MANIFEST_KEY_FLAKE_ATTR)
	}

	if m.DrvPathHash == "" || m.DrvOutputName == "" || m.DrvSha512 == "" {
		return nil, fmt.Errorf("missing or incomplete %s key", _MANIFEST_KEY_DRV)
	}

	if m.ImageSha512 == "" {
		return nil, fmt.Errorf("missing %s key", _MANIFEST_KEY_IMAGE_HASH)
	}

	if m.ImageMeasurementsSha512 == "" {
		return nil, fmt.Errorf("missing %s key", _MANIFEST_KEY_IMAGE_MEASUREMENTS_HASH)
	}

	return m, nil
}

func (m *Manifest) Encode(w io.Writer) error {
	sb := &strings.Builder{}
	sb.WriteString(fmt.Sprintf("%s %d\n", _MANIFEST_KEY_VERSION, m.Version))
	sb.WriteString(fmt.Sprintf("%s %s\n", _MANIFEST_KEY_NIX_VERSION, m.NixVersion))
	sb.WriteString(fmt.Sprintf("%s git+%s@%s\n", _MANIFEST_KEY_SOURCE, m.SourceUrl, m.SourceCommit))
	sb.WriteString(fmt.Sprintf("%s %s\n", _MANIFEST_KEY_FLAKE_ATTR, m.FlakeAttr))
	sb.WriteString(fmt.Sprintf("%s %s-%s.drv sha512:%s\n", _MANIFEST_KEY_DRV, m.DrvPathHash, m.DrvOutputName, m.DrvSha512))
	sb.WriteString(fmt.Sprintf("%s sha512:%s\n", _MANIFEST_KEY_IMAGE_HASH, m.ImageSha512))
	sb.WriteString(fmt.Sprintf("%s sha512:%s\n", _MANIFEST_KEY_IMAGE_MEASUREMENTS_HASH, m.ImageMeasurementsSha512))

	_, err := w.Write([]byte(sb.String()))
	return err
}
