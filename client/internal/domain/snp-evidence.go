package domain

import (
	"crypto/x509"
	"fmt"

	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

type snpHardwareEvidence struct {
	model  AMDSEVSNPModel
	report *AmdSevSnpAttestationReport
	raw    SignedRaw
}

func NewAMDSEVSNPHardwareEvidence(model AMDSEVSNPModel, snpEvidence *pb.Evidence) (HardwareEvidence[*AmdSevSnpAttestationReport], error) {
	// Raw attestation report reconstruction: Raw = [SignedRaw || Signature.Raw]

	if snpEvidence.SignedRaw == nil || snpEvidence.Signature == nil {
		return nil, fmt.Errorf("invalid SNP evidence: missing signed raw data or signature")
	}
	raw := make([]byte, len(snpEvidence.SignedRaw)+len(snpEvidence.Signature))
	copy(raw, snpEvidence.SignedRaw)
	copy(raw[len(snpEvidence.SignedRaw):], snpEvidence.Signature)

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
