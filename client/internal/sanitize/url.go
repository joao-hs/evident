package sanitize

import "net/url"

func RepoUrl(urlStr string) (string, error) {
	parsedUrl, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	parsedUrl.Fragment = ""
	return parsedUrl.String(), nil
}