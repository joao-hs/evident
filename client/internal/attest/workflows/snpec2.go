package workflows

import (
	"context"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

func RunSnpEc2AttestationWorkflow(
	ctx context.Context,
	client *grpc.Client,
	optCpuCount *uint8,
	optExpectedPCRs *domain.ExpectedPcrDigests,
	optPkgs packager.Packages,
	optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle,
) error {
	log.Get().Infoln("Getting evidence")
	getSnpEvidenceOutput, err := getsnpevidence.Task(ctx, getsnpevidence.Input{
		Client: client,
	})
	if err != nil {
		return err
	}

	log.Get().Infof("%+v", getSnpEvidenceOutput)
	return nil
}
