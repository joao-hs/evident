package domain

import (
	"crypto/x509"
	"errors"
)

type SignedRaw interface {
	// Returns the signature algorithm used
	Algorithm() x509.SignatureAlgorithm
	// Returns the bytes that were signed
	SignedData() []byte
	// Returns the signature bytes (ASN.1 encoded)
	Signature() []byte
	// Returns the concatenation of signed data and signature (for storage or transmission)
	Bytes() []byte
	// Returns the certificate chain of the signing key
	CertChain() *CertChain
	// Sets the certificate chain of the signing key
	SetCertChain(certChain *CertChain)
	// Verifies the signature over the signed data using the leaf certificate in the certificate chain
	IsOk() (bool, error)
}

type signedRaw struct {
	algorithm  x509.SignatureAlgorithm
	signedData []byte
	signature  []byte
	certChain  *CertChain
}

// Tip: to save memory, if raw contains signedData and signature, you can use slices of raw for signedData and signature.
func SignedRawFromBytes(algo x509.SignatureAlgorithm, signedData []byte, signature []byte, certChain *CertChain) SignedRaw {
	return &signedRaw{
		algorithm:  algo,
		signedData: signedData,
		signature:  signature,
		certChain:  certChain,
	}
}

func (sr *signedRaw) Algorithm() x509.SignatureAlgorithm {
	return sr.algorithm
}

func (sr *signedRaw) SignedData() []byte {
	return sr.signedData
}

func (sr *signedRaw) Signature() []byte {
	return sr.signature
}

func (sr *signedRaw) Bytes() []byte {
	// signedData || signature
	result := make([]byte, len(sr.signedData)+len(sr.signature))
	copy(result, sr.signedData)
	copy(result[len(sr.signedData):], sr.signature)
	return result
}

func (sr *signedRaw) CertChain() *CertChain {
	return sr.certChain
}

func (sr *signedRaw) SetCertChain(certChain *CertChain) {
	sr.certChain = certChain
}

func (sr *signedRaw) IsOk() (bool, error) {
	if sr.certChain == nil || len(sr.certChain.Certificates()) == 0 {
		return false, errors.New("no certificate chain available for signature verification")
	}

	leafCert := sr.certChain.Leaf()
	if leafCert == nil {
		return false, errors.New("no leaf certificate available for signature verification")
	}

	if err := leafCert.CheckSignature(sr.algorithm, sr.signedData, sr.signature); err != nil {
		// error indicates signature is not valid
		return false, nil
	}
	return true, nil
}

type CertChain struct {
	certs         []*x509.Certificate
	completeChain bool
}

func NewCertChain(leaf *x509.Certificate) *CertChain {
	if leaf == nil {
		panic("leaf certificate cannot be nil")
	}

	isSelfSigned := false
	if err := leaf.CheckSignatureFrom(leaf); err == nil {
		isSelfSigned = true
	}

	return &CertChain{certs: []*x509.Certificate{leaf}, completeChain: isSelfSigned}
}

func (cc *CertChain) AddParent(parent *x509.Certificate) error {
	if len(cc.certs) == 0 {
		panic("cannot add parent to an empty certificate chain")
	}

	if cc.completeChain {
		return errors.New("certificate chain is already complete")
	}

	err := cc.certs[len(cc.certs)-1].CheckSignatureFrom(parent)
	if err != nil {
		return err
	}

	if err := parent.CheckSignatureFrom(parent); err == nil {
		cc.completeChain = true
	}

	cc.certs = append(cc.certs, parent)
	return nil
}

func (cc *CertChain) Certificates() []*x509.Certificate {
	return cc.certs
}

func (cc *CertChain) Leaf() *x509.Certificate {
	if len(cc.certs) == 0 {
		return nil
	}
	return cc.certs[0]
}

func (cc *CertChain) Root() *x509.Certificate {
	if len(cc.certs) == 0 {
		return nil
	}
	return cc.certs[len(cc.certs)-1]
}
