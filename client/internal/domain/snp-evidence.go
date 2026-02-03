package domain

import (
	"crypto/x509"
)

type snpHardwareEvidence struct {
	model  AMDSEVSNPModel
	report *AmdSevSnpAttestationReport
	raw    SignedRaw
}

func NewAMDSEVSNPHardwareEvidence(model AMDSEVSNPModel, raw []byte) (HardwareEvidence[*AmdSevSnpAttestationReport], error) {
	report, err := NewAmdSevSnpAttestationReport(raw)
	if err != nil {
		return nil, err
	}

	signedRaw := SignedRawFromBytes(
		x509.ECDSAWithSHA384,
		report.SignedDataSlice(raw),
		report.SignatureSlice(raw),
		nil,
	)

	return &snpHardwareEvidence{
		model:  model,
		report: report,
		raw:    signedRaw,
	}, nil
}

func (he *snpHardwareEvidence) SecureHardwarePlatform() SecureHardwarePlatform {
	return he.report.ReportFrom()
}

func (he *snpHardwareEvidence) Report() *AmdSevSnpAttestationReport {
	return he.report
}

func (he *snpHardwareEvidence) Raw() SignedRaw {
	return he.raw
}
