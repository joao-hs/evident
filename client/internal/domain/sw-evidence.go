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

func (t *tpmSoftwareEvidence) CloudServiceProvider() CloudServiceProvider {
	return t.provider
}

func (t *tpmSoftwareEvidence) Report() *TpmReport {
	return t.report
}

func (t *tpmSoftwareEvidence) Raw() SignedRaw {
	return t.raw
}
