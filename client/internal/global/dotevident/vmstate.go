package dotevident

import "time"

/*
	state.json:
	{
		lastSeenState: (on/off/deleted)
		role: (control/worker)
		ipv4:
		evident-server-port:
		attestedAt: (date)
		attestationPolicy: (attestation-policy/gce/worker.policy)
		attestationResult: (pass/fail)
		attestationDetails:
			hardware:
				fresh: true
				measurements:
					launchDigest: (match/no-match)
				signature: anchoredInAMD
			software:
				fresh: true
				boot-measurements:
					firmware: (match/no-match/unknown)
					boot-selection: (match/no-match)
					unified-kernel-image: (match/no-match)
					file-system: (match/no-match)
				signature: (anchoredInGCE/anchoredInEC2/anchoredInAvm/anchoredInAMD)
	}
*/

type vmState struct {
	LastSeenState      vmHealth           `json:"Last Seen State"`
	VmType             string             `json:"VM Type"`
	Ipv4               string             `json:"IPv4"`
	EvidentPort        int                `json:"Evident Port"`
	AttestedAt         time.Time          `json:"Attested At,format:datetime"`
	AttestationPolicy  string             `json:"Attestation Policy"` // TODO decide
	AttestationResult  passfail           `json:"Attestation Result"`
	AttestationDetails attestationDetails `json:"Attestation Details"`
}

type attestationDetails struct {
	Hardware hwAttestationDetails `json:"hardware"`
	Software swAttestationDetails `json:"software"`
}

type hwAttestationDetails struct {
	Fresh           bool           `json:"Fresh"`
	Measurements    hwMeasurements `json:"Measurements"`
	SignatureAnchor anchoredIn     `json:"Signature Anchor"`
}

type hwMeasurements struct {
	LaunchDigest match `json:"Launch Digest"`
}

type swAttestationDetails struct {
	Fresh            bool           `json:"Fresh"`
	BootMeasurements swMeasurements `json:"Boot Measurements"`
	SignatureAnchor  anchoredIn     `json:"Signature Anchor"`
}

type swMeasurements struct {
	Firmware      match `json:"Firmware"`
	BootSelection match `json:"Boot Selection"`
	Uki           match `json:"Unified Kernel Image"`
	Fs            match `json:"Filesystem"`
}
