package servecertify

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/report"
)

func writeAttestationReport(reportInput report.ReportInput) (string, error) {
	reportInput.ComputeVerdict()

	tmpl, err := report.GetTemplate()
	if err != nil {
		return "", fmt.Errorf("failed to get report template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, reportInput); err != nil {
		return "", fmt.Errorf("failed to execute report template: %w", err)
	}

	reportFile, err := os.CreateTemp("", "evident-attestation-report-*.html")
	if err != nil {
		return "", fmt.Errorf("failed to create report file: %w", err)
	}
	defer reportFile.Close()

	if _, err := reportFile.Write(buf.Bytes()); err != nil {
		return "", fmt.Errorf("failed to write report file: %w", err)
	}

	log.Get().Infoln("Attestation report generated at", reportFile.Name())
	return reportFile.Name(), nil
}

func promptForCertificateApproval(ctx context.Context, reportPath string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	fmt.Fprintf(os.Stdout, "Approve certificate issuance? Review the report at %s [y/N]: ", reportPath)

	responseCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			responseCh <- scanner.Text()
			return
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
			return
		}
		errCh <- fmt.Errorf("stdin closed")
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case err := <-errCh:
		return false, err
	case response := <-responseCh:
		normalized := strings.TrimSpace(strings.ToLower(response))
		return normalized == "y" || normalized == "yes", nil
	}
}
