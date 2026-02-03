package gcekds

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
)

type GCEKDS interface {
	GetIssuerCertificate(childCert *x509.Certificate) (*x509.Certificate, error)
}

type gcekds struct {
	httpClient   *http.Client
	fetchedCache map[string]*x509.Certificate
}

var (
	instance GCEKDS
	once     sync.Once
)

func GetInstance() GCEKDS {
	once.Do(func() {
		instance = &gcekds{
			httpClient: &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return fmt.Errorf("redirects are not allowed (redirected to %s)", req.URL.String())
				},
			},
			fetchedCache: make(map[string]*x509.Certificate),
		}
	})

	return instance
}

func (self *gcekds) GetIssuerCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	if childCert == nil {
		return nil, fmt.Errorf("nil certificate provided")
	}

	issuerCertURI, err := self.getCertificateEndorserURI(childCert)
	if err != nil {
		return nil, err
	}

	if cert, exists := self.fetchedCache[issuerCertURI]; exists {
		return cert, nil
	}

	resp, err := self.httpClient.Get(issuerCertURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer certificate from %s: %v", issuerCertURI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch issuer certificate from %s: received status code %d", issuerCertURI, resp.StatusCode)
	}

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer certificate data from response: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %v", err)
	}

	if err := childCert.CheckSignatureFrom(issuerCert); err != nil {
		return nil, fmt.Errorf("the fetched certificate is not the issuer of the provided certificate: %v", err)
	}

	self.fetchedCache[issuerCertURI] = issuerCert

	return issuerCert, nil
}

func (self *gcekds) getCertificateEndorserURI(cert *x509.Certificate) (string, error) {
	// GCE's TPM's certificates have the x509v3 Authority Information Access populated with the URI of the issuing CA
	if cert == nil {
		return "", fmt.Errorf("nil certificate provided")
	}

	if len(cert.IssuingCertificateURL) != 1 {
		return "", fmt.Errorf("expected exactly one issuing certificate URI, found %d", len(cert.IssuingCertificateURL))
	}

	uri := cert.IssuingCertificateURL[0]
	if matched, err := regexp.MatchString(
		`^http://[a-z-0-9]+.storage.googleapis.com/[a-z0-9]+/ca.crt$`,
		uri,
	); err == nil && matched {
		return uri, nil
	} else if err != nil {
		return "", fmt.Errorf("issuing certificate URI does not match expected format")
	}

	return "", fmt.Errorf("could not find issuing certificate URI in AIA extension")
}
