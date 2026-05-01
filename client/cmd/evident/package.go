package evident

import (
	"bytes"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/build"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/measure"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
)

var packageCmd = &cobra.Command{
	Use:   "package",
	Short: "Build, measure, and sign a VM package manifest",
	Long: `Builds a VM image from a Nix flake, measures it, and signs a package manifest.

Required flags: --variation. If --repo or --commit are not provided, they are derived from the git origin and HEAD commit in the flake directory.`,
	Example: `  evident package --variation my-variation --output-dir /etc/evident/trusted-packages`,
	Args:    cobra.NoArgs,
	PreRunE: preRunWithLogger,

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		nixFlakeDirPath, err := sanitize.NixFlakeDirFromPath(cmd.Flag("flake").Value.String())
		if err != nil {
			return err
		}
		variation, err := sanitize.ImageVariation(cmd.Flag("variation").Value.String())
		if err != nil {
			return err
		}
		outputDirPath, err := filepath.Abs(cmd.Flag("output-dir").Value.String())
		if err != nil {
			return err
		}

		repoFlag := strings.TrimSpace(cmd.Flag("repo").Value.String())
		var repoUrl string
		if repoFlag != "" {
			repoFlagNormalized, err := normalizeRepoURL(repoFlag)
			if err != nil {
				return err
			}
			repoUrl, err = sanitize.RepoUrl(repoFlagNormalized)
			if err != nil {
				return err
			}
		} else {
			repoUrlFromGit, err := gitOriginRepoURL(nixFlakeDirPath)
			if err != nil {
				return err
			}
			repoUrl, err = sanitize.RepoUrl(repoUrlFromGit)
			if err != nil {
				return err
			}
		}

		commitFlag := strings.TrimSpace(cmd.Flag("commit").Value.String())
		var commitHash string
		if commitFlag != "" {
			commitHash, err = sanitize.CommitHash(commitFlag)
			if err != nil {
				return err
			}
		} else {
			commitHashFromGit, err := gitHeadCommitHash(nixFlakeDirPath)
			if err != nil {
				return err
			}
			commitHash, err = sanitize.CommitHash(commitHashFromGit)
			if err != nil {
				return err
			}
		}

		hasChanges, err := gitHasUncommittedChanges(nixFlakeDirPath)
		if err != nil {
			return err
		}
		if hasChanges {
			log.Get().Warnf("uncommitted changes detected in %s; using HEAD commit %s for manifest metadata", nixFlakeDirPath, commitHash)
		}

		keyId, err := sanitize.KeyId(cmd.Flag("key").Value.String())
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		vmImageBuilder, err := build.NewVMImageBuilder()
		if err != nil {
			return err
		}

		vmImageMeasurer, err := measure.NewVMImageMeasurer()
		if err != nil {
			return err
		}

		pkg, err := packager.NewPackager(vmImageBuilder, vmImageMeasurer, keyId)
		if err != nil {
			return err
		}

		show, err := cmd.Flags().GetBool("show")
		if err != nil {
			panic("could not parse 'show' flag")
		}
		if show {
			log.Get().Infoln(pkg.GetEquivalentCommands(nixFlakeDirPath, variation, outputDirPath))
			return nil
		}

		err = pkg.Package(nixFlakeDirPath, variation, outputDirPath, repoUrl, commitHash)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	packageCmd.Flags().String("flake", "./flake.nix", "path to the nix flake")
	packageCmd.Flags().String("variation", "", "package variation inside the nix flake")
	packageCmd.Flags().StringP("output-dir", "o", "/etc/evident/trusted-packages", "output directory path where to store the built package")
	packageCmd.Flags().String("repo", "", "git repository url to include in the manifest file (default: git origin in the flake directory)")
	packageCmd.Flags().String("commit", "", "git commit hash to include in the manifest file (default: HEAD commit in the flake directory)")
	packageCmd.Flags().StringP("key", "k", "", "gpg key id to sign the manifest file (default gpg key if exists, otherwise aborts)")
	packageCmd.Flags().Bool("show", false, "show equivalent commands instead of executing them; default: false")
	cobra.CheckErr(packageCmd.MarkFlagRequired("variation"))
	rootCmd.AddCommand(packageCmd)
}

func gitOriginRepoURL(repoDir string) (string, error) {
	out, err := runGitCommand(repoDir, "remote", "get-url", "--all", "origin")
	if err != nil {
		return "", err
	}

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		return normalizeRepoURL(trimmed)
	}

	return "", fmt.Errorf("git origin url not found in %s", repoDir)
}

func gitHeadCommitHash(repoDir string) (string, error) {
	out, err := runGitCommand(repoDir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}

	commitHash := strings.TrimSpace(out)
	if commitHash == "" {
		return "", fmt.Errorf("empty git HEAD commit hash in %s", repoDir)
	}

	return commitHash, nil
}

func gitHasUncommittedChanges(repoDir string) (bool, error) {
	out, err := runGitCommand(repoDir, "status", "--porcelain")
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(out) != "", nil
}

func runGitCommand(repoDir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = strings.TrimSpace(stdout.String())
		}
		if errMsg == "" {
			errMsg = err.Error()
		}
		return "", fmt.Errorf("git %s failed: %s", strings.Join(args, " "), errMsg)
	}

	return stdout.String(), nil
}

func normalizeRepoURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty repo url")
	}

	if strings.Contains(trimmed, "://") {
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("invalid repo url %q: %w", raw, err)
		}
		if parsed.Host == "" {
			return "", fmt.Errorf("invalid repo url %q: missing host", raw)
		}

		path := strings.TrimPrefix(parsed.Path, "/")
		path = strings.TrimSuffix(path, "/")
		path = strings.TrimSuffix(path, ".git")
		if path == "" {
			return "", fmt.Errorf("invalid repo url %q: missing path", raw)
		}

		return fmt.Sprintf("https://%s/%s", parsed.Host, path), nil
	}

	withoutUser := trimmed
	if atIndex := strings.LastIndex(withoutUser, "@"); atIndex != -1 {
		withoutUser = withoutUser[atIndex+1:]
	}

	var host string
	var path string
	if strings.Contains(withoutUser, ":") {
		parts := strings.SplitN(withoutUser, ":", 2)
		host = parts[0]
		path = parts[1]
	} else if strings.Contains(withoutUser, "/") {
		parts := strings.SplitN(withoutUser, "/", 2)
		host = parts[0]
		path = parts[1]
	} else {
		return "", fmt.Errorf("unrecognized repo url format: %q", raw)
	}

	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, ".git")
	if host == "" || path == "" {
		return "", fmt.Errorf("invalid repo url %q", raw)
	}

	return fmt.Sprintf("https://%s/%s", host, path), nil
}
