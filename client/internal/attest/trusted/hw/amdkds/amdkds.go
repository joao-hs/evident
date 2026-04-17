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
	base                              = "https://kdsintf.amd.com/"
	certChainURIV1TemplateTermination = "cert_chain"
	crlURIV1TemplateTermination       = "crl"

	vcekV1Template = "vcek/v1/%s/%s" // 1st argument: productName (ASN.1 IA5String)
	vlekV1Template = "vlek/v1/%s/%s" // 1st argument: productName (ASN.1 IA5String)
)

func vcekCertChainURI(model domain.AMDSEVSNPModel) string {
	return fmt.Sprintf(base+vcekV1Template, model.String(), certChainURIV1TemplateTermination)
}

func vcekCRLURI(model domain.AMDSEVSNPModel) string {
	return fmt.Sprintf(base+vcekV1Template, model.String(), crlURIV1TemplateTermination)
}

func vcekURI(model domain.AMDSEVSNPModel, chipID string) string {
	return fmt.Sprintf(base+vcekV1Template, model.String(), chipID)
}

func vlekCertChainURI(model domain.AMDSEVSNPModel) string {
	return fmt.Sprintf(base+vlekV1Template, model.String(), certChainURIV1TemplateTermination)
}

func vlekCRLURI(model domain.AMDSEVSNPModel) string {
	return fmt.Sprintf(base+vlekV1Template, model.String(), crlURIV1TemplateTermination)
}

type AMDKDS interface {
	FetchVcekCRL(model domain.AMDSEVSNPModel) error
	FetchVlekCRL(model domain.AMDSEVSNPModel) error
	GetAsk(model domain.AMDSEVSNPModel) (*x509.Certificate, error)
	GetAsvk(model domain.AMDSEVSNPModel) (*x509.Certificate, error)
	GetArk(model domain.AMDSEVSNPModel) (*x509.Certificate, error)
	GetVCEKParentChain(model domain.AMDSEVSNPModel) ([]*x509.Certificate, error)
	GetVLEKParentChain(model domain.AMDSEVSNPModel) ([]*x509.Certificate, error)
}

type amdkds struct {
	httpClient             *http.Client
	ARK                    map[domain.AMDSEVSNPModel]*x509.Certificate // map[productName]ARK
	ASK                    map[domain.AMDSEVSNPModel]*x509.Certificate // map[productName]ASK
	ASVK                   map[domain.AMDSEVSNPModel]*x509.Certificate // map[productName]ASVK
	vcekCertRevocationList *x509.RevocationList
	lastVcekCRLFetch       time.Time
	vlekCertRevocationList *x509.RevocationList
	lastVlekCRLFetch       time.Time
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
			ARK:                    make(map[domain.AMDSEVSNPModel]*x509.Certificate),
			ASK:                    make(map[domain.AMDSEVSNPModel]*x509.Certificate),
			ASVK:                   make(map[domain.AMDSEVSNPModel]*x509.Certificate),
			vcekCertRevocationList: nil,
			lastVcekCRLFetch:       time.Time{},
			vlekCertRevocationList: nil,
			lastVlekCRLFetch:       time.Time{},
		}
	})
	return instance
}

func (a *amdkds) FetchVcekCRL(model domain.AMDSEVSNPModel) error {
	if !a.lastVcekCRLFetch.IsZero() && time.Since(a.lastVcekCRLFetch) < 24*time.Hour && a.vcekCertRevocationList != nil {
		return nil
	}

	url := vcekCRLURI(model)
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

	a.vcekCertRevocationList = revocationList
	a.lastVcekCRLFetch = time.Now()

	if revocationList.RevokedCertificateEntries == nil {
		return nil
	}

	return nil
}

func (a *amdkds) FetchVlekCRL(model domain.AMDSEVSNPModel) error {
	if !a.lastVlekCRLFetch.IsZero() && time.Since(a.lastVlekCRLFetch) < 24*time.Hour && a.vlekCertRevocationList != nil {
		return nil
	}

	url := vlekCRLURI(model)
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

	a.vlekCertRevocationList = revocationList
	a.lastVlekCRLFetch = time.Now()

	if revocationList.RevokedCertificateEntries == nil {
		return nil
	}

	return nil
}

func (a *amdkds) GetVCEKParentChain(model domain.AMDSEVSNPModel) ([]*x509.Certificate, error) {
	if a.ARK[model] != nil && a.ASK[model] != nil {
		return []*x509.Certificate{a.ASK[model], a.ARK[model]}, nil
	}

	url := vcekCertChainURI(model)
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

func (a *amdkds) GetVLEKParentChain(model domain.AMDSEVSNPModel) ([]*x509.Certificate, error) {
	if a.ARK[model] != nil && a.ASVK[model] != nil {
		return []*x509.Certificate{a.ASK[model], a.ASVK[model]}, nil
	}

	url := vlekCertChainURI(model)
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
	a.ASVK[model] = certChain[0]
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

func (a *amdkds) GetAsvk(model domain.AMDSEVSNPModel) (*x509.Certificate, error) {
	if a.ASVK[model] != nil {
		return a.ASVK[model], nil
	}

	_, err := a.GetVLEKParentChain(model)
	if err != nil {
		return nil, err
	}

	return a.ASVK[model], nil
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
