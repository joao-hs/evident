package attest

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
)

func AttestTargets(ctx context.Context, endpoints map[string]int32, cpuCount uint8, ec2InstanceIDs map[string]string, securePlatformStr string, cloudProviderStr string, expectedPCRsBytes []byte) (map[string]error, error) {
	addressEndpoints := make(map[netip.Addr]uint16)
	for ip, port := range endpoints {
		targetIp, err := sanitize.TargetIP(ip)
		if err != nil {
			return nil, err
		}
		addressEndpoints[targetIp] = uint16(port)
	}

	securePlatform, err := sanitize.SecurePlatform(securePlatformStr)
	if err != nil {
		return nil, err
	}

	cloudProvider, err := sanitize.CloudServiceProvider(cloudProviderStr)
	if err != nil {
		return nil, err
	}

	var expectedPCRs domain.ExpectedPcrDigests
	err = json.Unmarshal(expectedPCRsBytes, &expectedPCRs)
	if err != nil {
		return nil, err
	}

	verifier, err := attest.NewVerifierWithContext(ctx, securePlatform, cloudProvider)
	if err != nil {
		return nil, err
	}

	resultCh := make(chan struct {
		ip  string
		err error
	}, len(addressEndpoints))
	wg := sync.WaitGroup{}
	wg.Add(len(addressEndpoints))
	for ip, port := range addressEndpoints {
		go func() {
			// ensure that wg.Wait() unblocks
			defer wg.Done()

			var optEc2InstanceID *string = nil
			ec2InstanceId, ok := ec2InstanceIDs[ip.String()]
			if ok && cloudProvider == domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS {
				optEc2InstanceID = &ec2InstanceId
			}

			_, err := verifier.Attest(ip, port, &cpuCount, optEc2InstanceID, &expectedPCRs, nil)

			// ensure that this go routine will not be stuck sending to channel upon context cancellation
			select {
			case resultCh <- struct {
				ip  string
				err error
			}{
				ip:  ip.String(),
				err: err,
			}:
			case <-ctx.Done():
				return
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	resultMap := make(map[string]error)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res, ok := <-resultCh:
			if !ok {
				return resultMap, nil
			}
			resultMap[res.ip] = res.err
		}
	}
}
