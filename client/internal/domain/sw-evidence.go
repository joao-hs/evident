package domain

import "crypto/x509"

type tpmSoftwareEvidence struct {
	provider CloudServiceProvider
	report   *TpmReport
	raw      SignedRaw
}

func NewTPMSoftwareEvidence(provider CloudServiceProvider, quoted []byte, signature []byte) (SoftwareEvidence, error) {
	report, err := NewTpmReport(quoted)
	if err != nil {
		return nil, err
	}

	signedRaw := SignedRawFromBytes(
		x509.ECDSAWithSHA256,
		quoted,
		signature,
		nil,
	)

	return &tpmSoftwareEvidence{
		provider: provider,
		report:   report,
		raw:      signedRaw,
	}, nil
}

func (self *tpmSoftwareEvidence) CloudServiceProvider() CloudServiceProvider {
	return self.provider
}

func (self *tpmSoftwareEvidence) Report() *TpmReport {
	return self.report
}

func (self *tpmSoftwareEvidence) Raw() SignedRaw {
	return self.raw
}
