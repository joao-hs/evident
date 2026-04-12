package amdkds

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

const (
	base                       = "https://kdsintf.amd.com/"
	vcekCertChainURIV1Template = "vcek/v1/%s/cert_chain" // productName (ASN.1 IA5String)
	vcekCRLURIV1Template       = "vcek/v1/%s/crl"        // productName (ASN.1 IA5String)
	vcekURIV1Template          = "vcek/v1/%s/%s"         // productName (ASN.1 IA5String), chipID (ASN.1 OCTET STRING)
)

type AMDKDS interface {
	FetchCRL(model domain.AMDSEVSNPModel) error
	GetVCEKParentChain(model domain.AMDSEVSNPModel) ([]*x509.Certificate, error)
	GetAsk(model domain.AMDSEVSNPModel) (*x509.Certificate, error)
	GetArk(model domain.AMDSEVSNPModel) (*x509.Certificate, error)
}

type amdkds struct {
	httpClient         *http.Client
	ARK                map[domain.AMDSEVSNPModel]*x509.Certificate // map[productName]ARK
	ASK                map[domain.AMDSEVSNPModel]*x509.Certificate // map[productName]ASK
	certRevocationList *x509.RevocationList
	lastCRLFetch       time.Time
}

var (
	instance AMDKDS
	once     sync.Once
)

func GetInstance() AMDKDS {
	once.Do(func() {
		instance = &amdkds{
			httpClient: &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return fmt.Errorf("redirects are not allowed (redirected to %s)", req.URL.String())
				},
			},
			ARK:                make(map[domain.AMDSEVSNPModel]*x509.Certificate),
			ASK:                make(map[domain.AMDSEVSNPModel]*x509.Certificate),
			certRevocationList: nil,
			lastCRLFetch:       time.Time{},
		}
	})
	return instance
}

func (a *amdkds) FetchCRL(model domain.AMDSEVSNPModel) error {
	if !a.lastCRLFetch.IsZero() && time.Since(a.lastCRLFetch) < 24*time.Hour && a.certRevocationList != nil {
		return nil
	}

	url := fmt.Sprintf(base+vcekCRLURIV1Template, model.String())
	resp, err := a.httpClient.Get(url)
	if err != nil {
		log.Get().Errorf("Error making GET request: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.TLS.Version != tls.VersionTLS13 && resp.TLS.Version != tls.VersionTLS12 {
		log.Get().Errorf("Insecure TLS version: %x", resp.TLS.Version)
		return fmt.Errorf("insecure TLS version: %x", resp.TLS.Version)
	}

	if resp.StatusCode != 200 {
		log.Get().Errorf("Non-200 response: %d", resp.StatusCode)
		return fmt.Errorf("non-200 response: %d", resp.StatusCode)
	}

	crlDer, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Get().Errorf("Error reading response body: %v", err)
		return err
	}

	revocationList, err := x509.ParseRevocationList(crlDer)
	if err != nil {
		log.Get().Errorf("Error parsing CRL: %v", err)
		return err
	}

	a.certRevocationList = revocationList
	a.lastCRLFetch = time.Now()

	if revocationList.RevokedCertificateEntries == nil {
		return nil
	}

	return nil
}

func (a *amdkds) GetVCEKParentChain(model domain.AMDSEVSNPModel) ([]*x509.Certificate, error) {
	if a.ARK[model] != nil && a.ASK[model] != nil {
		return []*x509.Certificate{a.ASK[model], a.ARK[model]}, nil
	}

	url := fmt.Sprintf(base+vcekCertChainURIV1Template, model.String())
	resp, err := a.httpClient.Get(url)
	if err != nil {
		log.Get().Errorf("Error making GET request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.TLS.Version != tls.VersionTLS13 && resp.TLS.Version != tls.VersionTLS12 {
		log.Get().Errorf("Insecure TLS version: %x", resp.TLS.Version)
		return nil, fmt.Errorf("insecure TLS version: %x", resp.TLS.Version)
	}

	if resp.StatusCode != 200 {
		log.Get().Errorf("Non-200 response: %d", resp.StatusCode)
		return nil, fmt.Errorf("non-200 response: %d", resp.StatusCode)
	}

	certificatePemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Get().Errorf("Error reading response body: %v", err)
		return nil, err
	}

	certChain, err := parseCertificateChain(certificatePemBytes)
	if err != nil {
		log.Get().Errorf("Error parsing certificate chain: %v", err)
		return nil, err
	}

	a.ARK[model] = certChain[1]
	a.ASK[model] = certChain[0]
	return certChain, nil
}

func (a *amdkds) GetAsk(model domain.AMDSEVSNPModel) (*x509.Certificate, error) {
	if a.ASK[model] != nil {
		return a.ASK[model], nil
	}

	_, err := a.GetVCEKParentChain(model)
	if err != nil {
		return nil, err
	}

	return a.ASK[model], nil
}

func (a *amdkds) GetArk(model domain.AMDSEVSNPModel) (*x509.Certificate, error) {
	if a.ARK[model] != nil {
		return a.ARK[model], nil
	}

	_, err := a.GetVCEKParentChain(model)
	if err != nil {
		return nil, err
	}

	return a.ARK[model], nil
}

// Utils

func isCertificateRevoked(cert *x509.Certificate, crl *x509.RevocationList) bool {
	if crl == nil {
		return false
	}

	if cert.Issuer.SerialNumber != crl.Issuer.SerialNumber {
		fmt.Println("Warning: certificate issuer does not match CRL issuer")
	}

	for _, revokedCert := range crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return true
		}
	}

	return false
}

func parseCertificateChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var derBytesCertChain [][]byte = [][]byte{}
	var block *pem.Block
	var rest []byte = pemBytes
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		derBytesCertChain = append(derBytesCertChain, block.Bytes)
	}

	if len(derBytesCertChain) != 2 {
		return nil, fmt.Errorf("certificate chain must contain exactly two PEM blocks")
	}

	cert1, err := x509.ParseCertificate(derBytesCertChain[0])
	if err != nil {
		return nil, err
	}

	cert2, err := x509.ParseCertificate(derBytesCertChain[1])
	if err != nil {
		return nil, err
	}

	return []*x509.Certificate{cert1, cert2}, nil
}

func parseCertificate(derBytes []byte) (*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	if len(certs) > 1 {
		log.Get().Warnln("Multiple certificates found, using the first one")
	}
	return certs[0], nil
}
