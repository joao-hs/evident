package report

import (
	"embed"
	"text/template"
)

// CheckStatus controls the indicator color and tag styling in the rendered HTML.
// Values must match the CSS class suffixes: "pass", "fail", "skip", "info".
type CheckStatus string

//go:embed template
var reportTemplateFS embed.FS

const (
	StatusPass CheckStatus = "pass"
	StatusFail CheckStatus = "fail"
	StatusSkip CheckStatus = "skip" // "Skipped due to prior error"
	StatusInfo CheckStatus = "info" // Informational only (e.g. processor model)
)

// CheckResult holds the data for a single attestation check item.
// Tag is the short label shown in the collapsed row (e.g. "Valid", "Mismatch", "Genoa").
// Detail is the full explanation shown when the row is expanded — may contain HTML
// (e.g. <code> tags for key identifiers).
type CheckResult struct {
	Status CheckStatus
	Tag    string
	Detail string // May contain safe HTML like <code>sha256:...</code>
}

// ReportInput is the top-level struct passed to the HTML template.
type ReportInput struct {
	// Header metadata
	IpAddress     string
	Timestamp     string // RFC3339
	CloudProvider string // "AWS", "GCP"
	ClientVersion string // e.g. "v0.9.3"

	// Overall verdict
	AllPassed bool
	FailCount int

	// Section 1: Evidence Integrity

	// Additional artifacts bundle retrieval
	Q1 CheckResult
	// Additional artifacts bundle signature
	Q2 CheckResult
	// Additional artifacts bundle contents validity
	Q3 CheckResult
	// Evidence bundle retrieval
	Q4 CheckResult
	// Evidence bundle signature
	Q5 CheckResult
	// Hardware evidence presence
	Q6 CheckResult
	// Software evidence presence
	Q7 CheckResult
	// Hardware evidence signature
	Q8 CheckResult
	// Software evidence signature
	Q9 CheckResult
	// AMD SEV-SNP processor model (typically StatusInfo)
	Q10 CheckResult

	// Section 2: Evidence Trustworthiness

	// Hardware evidence key endorsement (AMD root of trust)
	Q11 CheckResult
	// Hardware evidence freshness
	Q12 CheckResult
	// Software evidence key endorsement (cloud provider root of trust)
	Q13 CheckResult
	// Software evidence freshness
	Q14 CheckResult

	// Section 3: Measurement Reproducibility

	// Hardware evidence measurements
	Q15 CheckResult
	// Software evidence measurements
	Q16 CheckResult

	// Section 4: Bindings

	// Instance key bound to hardware evidence
	Q17 CheckResult
	// Instance key bound to software evidence
	Q18 CheckResult
}

func GetTemplate() (*template.Template, error) {
	return template.ParseFS(reportTemplateFS, "template/report.html")
}

func (r *ReportInput) ComputeVerdict() {
	r.AllPassed = r.Q1.Status != StatusFail &&
		r.Q2.Status != StatusFail &&
		r.Q3.Status != StatusFail &&
		r.Q4.Status != StatusFail &&
		r.Q5.Status != StatusFail &&
		r.Q6.Status != StatusFail &&
		r.Q7.Status != StatusFail &&
		r.Q8.Status != StatusFail &&
		r.Q9.Status != StatusFail &&
		// Q10 is informational only, does not affect overall pass/fail
		r.Q11.Status != StatusFail &&
		r.Q12.Status != StatusFail &&
		r.Q13.Status != StatusFail &&
		r.Q14.Status != StatusFail &&
		r.Q15.Status != StatusFail &&
		r.Q16.Status != StatusFail &&
		r.Q17.Status != StatusFail &&
		r.Q18.Status != StatusFail

	r.FailCount = 0
	checks := []CheckResult{
		r.Q1, r.Q2, r.Q3, r.Q4, r.Q5, r.Q6, r.Q7, r.Q8, r.Q9,
		// Skip Q10 since it's informational only
		r.Q11, r.Q12, r.Q13, r.Q14, r.Q15, r.Q16, r.Q17, r.Q18,
	}
	for _, check := range checks {
		if check.Status == StatusFail {
			r.FailCount++
		}
	}
}

// ──────────────────────────────────────────────────────────────
// Example construction (for reference):
//
//   input := ReportInput{
//       InstanceID:    "i-0a1b2c3d4e5f67890",
//       Timestamp:     time.Now().UTC().Format(time.RFC3339),
//       CloudProvider: "AWS",
//       ClientVersion: "v0.9.3",
//       AllPassed:     false,
//       FailCount:     1,
//       Q1: CheckResult{
//           Status: StatusPass,
//           Tag:    "Fetched",
//           Detail: "Yes, the additional artifacts bundle was fetched from the Evident server.",
//       },
//       Q2: CheckResult{
//           Status: StatusPass,
//           Tag:    "Valid",
//           Detail: "Yes, the additional artifacts bundle was correctly signed by the instance key identified by <code>sha256:a3f1...c892</code>.",
//       },
//       // ... etc
//       Q15: CheckResult{
//           Status: StatusFail,
//           Tag:    "Mismatch",
//           Detail: "No, this is a known <code>github.com/aws/uefi/issues/19</code>. Could indicate a version mismatch of the published vs. production firmware.",
//       },
//   }
