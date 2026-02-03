package domain

type SecureHardwarePlatformReport interface {
	ReportFrom() SecureHardwarePlatform
}

type Evidence[R SecureHardwarePlatformReport] struct {
	HardwareEvidence HardwareEvidence[R]
	SoftwareEvidence SoftwareEvidence
}

type HardwareEvidence[R SecureHardwarePlatformReport] interface {
	SecureHardwarePlatform() SecureHardwarePlatform

	Report() R

	Raw() SignedRaw
}

// ! assuming TPM-based software evidence, therefore, no generics needed
type SoftwareEvidence interface {
	CloudServiceProvider() CloudServiceProvider

	Report() *TpmReport

	Raw() SignedRaw
}
