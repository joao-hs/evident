package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence/getsnpevidencesubtasks"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence/makecred"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

func waitForEnter(hostIP, stageMsg string) {
	fmt.Println(stageMsg)
	fmt.Print("Press Enter to continue...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')

	cmd := exec.Command("nc", "-w", "1", hostIP, "5005")
	cmd.Stdin = strings.NewReader("start\n")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to send netcat signal to %s:5005: %v\n", hostIP, err)
	}
}

func runConcurrent(ipAddress string, cloudprovider domain.CloudServiceProvider, n int) {
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(workerID int) {
			defer wg.Done()

			// create a new child context with i as indentifier
			ctx := context.WithValue(context.Background(), "workerID", workerID)

			cfg := config.DefaultConfig()
			cfg.Addr = fmt.Sprintf("%s:5000", ipAddress)
			cfg.Timeout = 1 * time.Minute

			client, err := grpc.NewAttesterServiceClient(&cfg)
			if err != nil {
				panic(err)
			}

			resp, err := getsnpevidencesubtasks.FetchAdditionalArtifactsBundle(ctx, client)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[worker %d] error while calling FetchAdditionalArtifactsBundle: %v\n", workerID, err)
				return
			}
			fmt.Printf("[worker %d] successfully completed FetchAdditionalEvidenceBundle call\n", workerID)

			instanceKey := resp.GetInstanceKey()
			if instanceKey == nil {
				fmt.Fprintf(os.Stderr, "[worker %d] instance key is nil in FetchAdditionalArtifactsBundle response\n", workerID)
				return
			}
			pbCertificate := instanceKey.GetCertificate()
			if pbCertificate == nil {
				fmt.Fprintf(os.Stderr, "[worker %d] certificate is nil in instance key of FetchAdditionalArtifactsBundle response\n", workerID)
				return
			}

			cert, err := crypto.ParseCertificate(pbCertificate)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[worker %d] error while parsing certificate: %v\n", workerID, err)
				return
			}

			var activateCredentialBundle *pb.ActivateCredentialBundle
			if cloudprovider == domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS {
				makeCredentialInput := resp.GetMakeCredentialInput()
				if makeCredentialInput == nil {
					fmt.Fprintf(os.Stderr, "[worker %d] make credential input is nil for AWS\n", workerID)
					return
				}

				ekEc, _, err := crypto.ParsePublicKey(makeCredentialInput.GetTpmEndorsementKey())
				if err != nil {
					fmt.Fprintf(os.Stderr, "[worker %d] error while parsing TPM endorsement key: %v\n", workerID, err)
					return
				}

				akName := makeCredentialInput.GetTpmAttestationKeyName()
				if akName == nil {
					fmt.Fprintf(os.Stderr, "[worker %d] TPM attestation key name is nil for AWS\n", workerID)
					return
				}

				secret := getsnpevidencesubtasks.GenerateRandomBytes()
				makeCredentialResult, err := makecred.ECC(ekEc, secret[:], akName, makecred.Ec2EccEkParams())
				if err != nil {
					fmt.Fprintf(os.Stderr, "[worker %d] error while creating ActivateCredentialBundle using makecred for AWS: %v\n", workerID, err)
					return
				}

				activateCredentialBundle = &pb.ActivateCredentialBundle{
					CredentialBlob:  makeCredentialResult.CredentialBlob,
					EncryptedSecret: makeCredentialResult.EncryptedSecret,
				}
			}

			nonce := getsnpevidencesubtasks.GenerateRandomBytes()
			_, err = getsnpevidencesubtasks.FetchEvidenceBundle(ctx, client, &pb.GetEvidenceRequest{
				Nonce:                    nonce[:],
				ActivateCredentialBundle: activateCredentialBundle,
			}, cert)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[worker %d] error while calling FetchEvidenceBundle: %v\n", workerID, err)
				return
			}
			fmt.Printf("[worker %d] successfully completed FetchEvidenceBundle call\n", workerID)
		}(i)
	}

	wg.Wait()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <host-ip-address> <ec2|gce>\n", os.Args[0])
		os.Exit(1)
	}

	hostIP := os.Args[1]
	cloudprovider, err := sanitize.CloudServiceProvider(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid cloud provider argument: %v\n", err)
		os.Exit(1)
	}

	cfg := config.DefaultConfig()
	cfg.Addr = fmt.Sprintf("%s:5000", hostIP)
	cfg.Timeout = 30 * time.Second

	client, err := grpc.NewAttesterServiceClient(&cfg)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Optional mode: concurrent
	// usage: <host-ip-address> <ec2|gce> concurrent <N>
	if len(os.Args) >= 4 && os.Args[3] == "concurrent" {
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "usage for concurrent mode: %s <host-ip-address> <ec2|gce> concurrent <N>\n", os.Args[0])
			os.Exit(1)
		}

		n, convErr := strconv.Atoi(os.Args[4])
		if convErr != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "invalid concurrent worker count %q; expected positive integer\n", os.Args[4])
			os.Exit(1)
		}

		waitForEnter(hostIP, "Concurrent stage: concurrently calling FetchAdditionalArtifactsBundle and FetchEvidenceBundle with "+strconv.Itoa(n)+" workers. Make sure to monitor the server's resource usage during this stage.")

		runConcurrent(hostIP, cloudprovider, n)
		return
	}

	waitForEnter(hostIP, "Stage 1: sequentially calling FetchAdditionalArtifactsBundle for 30 seconds")

	deadline := time.Now().Add(30 * time.Second)
	var lastResp *pb.AdditionalArtifactsBundle
	for time.Now().Before(deadline) {
		resp, callErr := getsnpevidencesubtasks.FetchAdditionalArtifactsBundle(ctx, client)
		if callErr != nil {
			fmt.Fprintf(os.Stderr, "error while calling FetchAdditionalArtifactsBundle: %v\n", callErr)
			continue
		}
		lastResp = resp
	}

	if lastResp == nil {
		panic("no successful FetchAdditionalArtifactsBundle response received within 30 seconds")
	}

	instanceKey := lastResp.GetInstanceKey()
	if instanceKey == nil {
		panic("instance key is nil in last successful FetchAdditionalArtifactsBundle response")
	}
	pbCertificate := instanceKey.GetCertificate()
	if pbCertificate == nil {
		panic("certificate is nil in instance key of last successful FetchAdditionalArtifactsBundle response")
	}
	cert, err := crypto.ParseCertificate(pbCertificate)
	if err != nil {
		panic(fmt.Errorf("error while parsing certificate in instance key of last successful FetchAdditionalArtifactsBundle response: %w", err))
	}

	var activateCredentialFunc func() *pb.ActivateCredentialBundle
	if cloudprovider == domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS {
		makeCredentialInput := lastResp.GetMakeCredentialInput()
		if makeCredentialInput == nil {
			panic("make credential input is nil in last successful FetchAdditionalArtifactsBundle response, cannot proceed with AWS-specific ActivateCredentialBundle")
		}

		ekEc, _, err := crypto.ParsePublicKey(makeCredentialInput.GetTpmEndorsementKey())
		if err != nil {
			panic(fmt.Errorf("error while parsing TPM endorsement key in make credential input of last successful FetchAdditionalArtifactsBundle response: %w", err))
		}

		akName := makeCredentialInput.GetTpmAttestationKeyName()
		if akName == nil {
			panic("TPM attestation key name is nil in make credential input of last successful FetchAdditionalArtifactsBundle response, cannot proceed with AWS-specific ActivateCredentialBundle")
		}

		activateCredentialFunc = func() *pb.ActivateCredentialBundle {
			secret := getsnpevidencesubtasks.GenerateRandomBytes()
			makeCredentialResult, err := makecred.ECC(ekEc, secret[:], akName, makecred.Ec2EccEkParams())
			if err != nil {
				panic(fmt.Errorf("error while creating ActivateCredentialBundle using makecred for AWS: %v\n", err))
			}
			return &pb.ActivateCredentialBundle{
				CredentialBlob:  makeCredentialResult.CredentialBlob,
				EncryptedSecret: makeCredentialResult.EncryptedSecret,
			}
		}
	} else {
		activateCredentialFunc = func() *pb.ActivateCredentialBundle {
			return nil
		}
	}

	waitForEnter(hostIP, "Stage 2: calling FetchEvidenceBundle with signing key and parsed certificate")

	deadline = time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		nonce := getsnpevidencesubtasks.GenerateRandomBytes()
		_, err = getsnpevidencesubtasks.FetchEvidenceBundle(ctx, client, &pb.GetEvidenceRequest{
			Nonce:                    nonce[:],
			ActivateCredentialBundle: activateCredentialFunc(),
		}, cert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while calling FetchEvidenceBundle: %v\n", err)
			continue
		}
	}

}
