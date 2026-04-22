package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence/getsnpevidencesubtasks"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

type Sample struct {
	TsStart time.Time
	RTT     time.Duration
	Err     bool
}

type StepResult struct {
	Concurrency int     `json:"concurrency"`
	TsStart     int64   `json:"ts_start"`
	TsEnd       int64   `json:"ts_end"`
	Total       int     `json:"total"`
	Errors      int     `json:"errors"`
	RPS         float64 `json:"rps"`
}

type TestResult struct {
	HostIp        string       `json:"host_ip"`
	CloudProvider string       `json:"cloud_provider"`
	CpuCount      int          `json:"cpu_count"`
	Region        string       `json:"region"`
	Steps         []StepResult `json:"steps"`
}

const (
	timeoutPerRequest = 2 * time.Minute
)

func doFetchEvidence(ctx context.Context, client *grpc.AttesterServiceClient) *Sample {
	sample := &Sample{}
	nonce := getsnpevidencesubtasks.GenerateRandomBytes()
	sample.TsStart = time.Now()
	_, err := client.GetEvidence(ctx, &pb.GetEvidenceRequest{
		Nonce: nonce[:],
	})
	sample.RTT = time.Since(sample.TsStart)
	if err != nil {
		sample.Err = true
	} else {
		sample.Err = false
	}
	return sample
}

func sustainedLoad(cfg *config.Config, n int, sampleCh chan<- *Sample, deadline time.Time) {
	ctx := context.Background()

	clients := make([]*grpc.AttesterServiceClient, n)
	for i := 0; i < n; i++ {
		client, err := grpc.NewAttesterServiceClient(cfg)
		if err != nil {
			panic(err)
		}
		clients[i] = client
	}

	for i := 0; i < n; i++ {
		go func(client *grpc.AttesterServiceClient) {
			defer client.Close()
			for time.Now().Before(deadline) {
				sample := doFetchEvidence(ctx, client)
				sampleCh <- sample
			}
		}(clients[i])
	}
}

func progressiveLoad(hostIp string, cloudProvider domain.CloudServiceProvider) TestResult {
	cfg := config.DefaultConfig()
	cfg.Timeout = timeoutPerRequest
	cfg.Addr = fmt.Sprintf("%s:5000", hostIp)
	cfg.MaxRetries = 1

	loadLevels := [...]int{1, 2, 4, 6, 8, 10, 12, 15, 20, 25, 30, 35, 40, 50}
	clearingTime := [...]int{1, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0}

	results := make([]StepResult, 0)
	for i, loadLevel := range loadLevels {
		deadline := time.Now().Add(3 * time.Minute)
		sampleCh := make(chan *Sample, 1000)
		sustainedLoad(&cfg, loadLevel, sampleCh, deadline)

		samples := make([]*Sample, 0)
		for time.Now().Before(deadline.Add(timeoutPerRequest)) {
			select {
			case sample := <-sampleCh:
				samples = append(samples, sample)
			case <-time.After(timeoutPerRequest):
				break
			}
		}

		errCount := 0
		minTime := time.Now()
		maxTime := time.Time{}
		for _, sample := range samples {
			if sample.Err {
				errCount++
			}
			if sample.TsStart.Before(minTime) {
				minTime = sample.TsStart
			}
			if sample.TsStart.After(maxTime) {
				maxTime = sample.TsStart
			}
		}

		stepResult := StepResult{
			Concurrency: loadLevel,
			TsStart:     minTime.Unix(),
			TsEnd:       maxTime.Unix(),
			Total:       len(samples),
			Errors:      errCount,
			RPS:         float64(len(samples))/float64(maxTime.Sub(minTime).Seconds()) + 0.000001, // add small value to avoid division by zero
		}

		fmt.Printf("Completed load level for %s in %s. %s\n", hostIp, cloudProvider.String(), mustMarshalJson(stepResult))

		results = append(results, stepResult)

		close(sampleCh)

		time.Sleep(time.Duration(clearingTime[i]) * time.Minute)
	}

	return TestResult{
		HostIp:        hostIp,
		CloudProvider: cloudProvider.String(),
		Steps:         results,
	}
}

func main() {
	// usage: ./stresstester <host-ip-address>:<cloud-provider> [...]
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <host-ip-address>:<ec2|gce> [...]\n", os.Args[0])
		os.Exit(1)
	}

	argSplit := make([][]string, len(os.Args)-1)
	for i := 1; i < len(os.Args); i++ {
		argSplit[i-1] = []string{}
		for _, part := range os.Args[i] {
			if part == ':' {
				argSplit[i-1] = append(argSplit[i-1], "")
			} else {
				if len(argSplit[i-1]) == 0 {
					argSplit[i-1] = append(argSplit[i-1], "")
				}
				argSplit[i-1][len(argSplit[i-1])-1] += string(part)
			}
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	for _, arg := range argSplit {
		if len(arg) != 3 {
			fmt.Fprintf(os.Stderr, "invalid argument format %q; expected <host-ip-address>:<cloud-provider>:<cpu-count>\n", arg)
			continue
		}

		hostIP := arg[0]
		cloudProvider, err := sanitize.CloudServiceProvider(arg[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid cloud provider argument %q: %v\n", arg[1], err)
			continue
		}
		cpuCount, err := strconv.Atoi(arg[2])
		if err != nil || cpuCount <= 0 {
			fmt.Fprintf(os.Stderr, "invalid cpu count argument %q: %v\n", arg[2], err)
			continue
		}

		go func(hostIp string, cloudProvider domain.CloudServiceProvider) {
			defer wg.Done()
			startTime := time.Now()

			fmt.Printf("Starting stress test for host %s on cloud provider %s...\n", hostIP, cloudProvider.String())
			results := progressiveLoad(hostIP, cloudProvider)
			fmt.Printf("Completed stress test for host %s on cloud provider %s.\n", hostIP, cloudProvider.String())
			// save to file
			filename := fmt.Sprintf("stresstest_result_%s_%s_%d.json", hostIP, cloudProvider.String(), startTime.Unix())
			file, err := os.Create(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating result file %q: %v\n", filename, err)
				fmt.Printf("Results: %s\n", mustMarshalJson(results))
				return
			}
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(results); err != nil {
				fmt.Fprintf(os.Stderr, "error encoding results to JSON for file %q: %v\n", filename, err)
				fmt.Printf("Results: %s\n", mustMarshalJson(results))
				return
			}
			fmt.Printf("Saved stress test results for host %s on cloud provider %s to file %q.\n", hostIP, cloudProvider.String(), filename)
			file.Close()
		}(hostIP, cloudProvider)

	}

	wg.Wait()
}

func mustMarshalJson(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("error marshaling to JSON: %v", err))
	}
	return string(b)
}
