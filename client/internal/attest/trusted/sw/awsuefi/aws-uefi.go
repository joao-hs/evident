package awsuefi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

const (
	AWS_UEFI_GITHUB_RELEASE_METADATA_URL = "https://api.github.com/repos/aws/uefi/releases/latest"
	AWS_UEFI_DOWNLOAD_URL_PREFIX         = "https://github.com/aws/uefi/releases/download/"
	AWS_UEFI_FIRMWARE_ASSET_NAME         = "ovmf_img.fd"
)

type Ec2FirmwareFetcher interface {
	FetchFirmwareBinary() ([]byte, error)
}

type ec2FirmwareFetcher struct {
	httpClient     *http.Client
	firmwareBinary []byte
}

var (
	instance Ec2FirmwareFetcher
	once     sync.Once
)

func GetInstance() Ec2FirmwareFetcher {
	once.Do(func() {
		instance = &ec2FirmwareFetcher{
			httpClient: &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return fmt.Errorf("redirects are not allowed (redirected to %s)", req.URL.String())
				},
			},
			firmwareBinary: nil,
		}
	})
	return instance
}

func (e *ec2FirmwareFetcher) FetchFirmwareBinary() ([]byte, error) {
	if e.firmwareBinary != nil {
		return e.firmwareBinary, nil
	}

	binary, err := e.downloadLatestFirmware()
	if err != nil {
		return nil, err
	}
	e.firmwareBinary = binary
	return e.firmwareBinary, nil
}

type githubReleaseMetadata struct {
	Assets []githubAsset `json:"assets"`
}
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func (e *ec2FirmwareFetcher) downloadLatestFirmware() ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, AWS_UEFI_GITHUB_RELEASE_METADATA_URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for latest firmware release: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest firmware release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from Github latest release API: %s", resp.Status)
	}

	var metadata githubReleaseMetadata
	err = json.NewDecoder(resp.Body).Decode(&metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to decode latest firmware release metadata: %w", err)
	}

	var firmwareDownloadURL string
	for _, asset := range metadata.Assets {
		if asset.Name == AWS_UEFI_FIRMWARE_ASSET_NAME {
			firmwareDownloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if firmwareDownloadURL == "" {
		return nil, fmt.Errorf("failed to find firmware asset in latest release")
	}
	if firmwareDownloadURL[:len(AWS_UEFI_DOWNLOAD_URL_PREFIX)] != AWS_UEFI_DOWNLOAD_URL_PREFIX {
		return nil, fmt.Errorf("unexpected firmware download URL: %s", firmwareDownloadURL)
	}
	if firmwareDownloadURL[len(firmwareDownloadURL)-len(AWS_UEFI_FIRMWARE_ASSET_NAME):] != AWS_UEFI_FIRMWARE_ASSET_NAME {
		return nil, fmt.Errorf("unexpected firmware asset name in download URL: %s", firmwareDownloadURL)
	}

	firmwareResp, err := e.httpClient.Get(firmwareDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download firmware binary: %w", err)
	}
	defer firmwareResp.Body.Close()

	if firmwareResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status when downloading firmware binary: %s", firmwareResp.Status)
	}

	firmwareBinary := make([]byte, firmwareResp.ContentLength)
	_, err = firmwareResp.Body.Read(firmwareBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to read firmware binary response body: %w", err)
	}

	return firmwareBinary, nil
}
