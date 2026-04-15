package getec2endorsedartifacts

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/sw/awsuefi"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	OptInstanceID *string
}

type Output struct {
	UefiBinary []byte
	EkEc       *ecdsa.PublicKey
	EkRsa      *rsa.PublicKey
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		dot        = dotevident.Get()
		path       string
		err        error
		zeroOutput Output
		output     Output
	)

	// Fetch EC2 firmware binary using AWS UEFI library

	log.Get().Debugf("Fetching EC2 firmware binary using AWS UEFI library")
	output.UefiBinary, err = awsuefi.GetInstance().FetchFirmwareBinary()
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to fetch firmware binary: %w", err)
	}
	path, err = dot.Store(output.UefiBinary)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store firmware binary in dot: %w", err)
	}
	log.Get().Debugf("Firmware binary stored in dot with path: %s", path)

	// Fetch EK using AWS SDK, if instance ID is provided

	if input.OptInstanceID != nil {
		log.Get().Debugf("Fetching EK certificate for instance ID %s using AWS SDK", *input.OptInstanceID)

		output.EkEc, err = getInstanceTpmEcEkPub(ctx, *input.OptInstanceID)
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to fetch EC EK public key: %w", err)
		}
		log.Get().Debugf("Successfully fetched EC EK public key for instance ID %s", *input.OptInstanceID)

		ekEcBytes, err := output.EkEc.Bytes()
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to get bytes of EC EK public key: %w", err)
		}
		path, err = dot.Store(ekEcBytes)
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to store EC EK public key in dot: %w", err)
		}
		log.Get().Debugf("EC EK public key stored in dot with path: %s", path)

		output.EkRsa, err = getInstanceTpmRsaEkPub(ctx, *input.OptInstanceID)
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to fetch RSA EK public key: %w", err)
		}
		log.Get().Debugf("Successfully fetched RSA EK public key for instance ID %s", *input.OptInstanceID)

		ekRsaBytes, err := x509.MarshalPKIXPublicKey(output.EkRsa)
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to marshal RSA EK public key: %w", err)
		}
		path, err = dot.Store(ekRsaBytes)
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to store RSA EK public key in dot: %w", err)
		}
		log.Get().Debugf("RSA EK public key stored in dot with path: %s", path)
	}
	return output, nil
}

func getInstanceTpmEcEkPub(ctx context.Context, instanceId string) (*ecdsa.PublicKey, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := ec2.NewFromConfig(cfg)

	out, err := client.GetInstanceTpmEkPub(ctx, &ec2.GetInstanceTpmEkPubInput{
		InstanceId: &instanceId,
		KeyType:    types.EkPubKeyTypeEccSecP384,
		KeyFormat:  types.EkPubKeyFormatDer,
	})
	if err != nil {
		return nil, fmt.Errorf("GetInstanceTpmEkPub: %w", err)
	}

	if out.KeyValue == nil {
		return nil, fmt.Errorf("response contained no key value")
	}

	der, err := base64.StdEncoding.DecodeString(*out.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("base64-decoding key value: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing DER public key: %w", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, not *ecdsa.PublicKey", pub)
	}

	return ecPub, nil
}

func getInstanceTpmRsaEkPub(ctx context.Context, instanceId string) (*rsa.PublicKey, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := ec2.NewFromConfig(cfg)

	out, err := client.GetInstanceTpmEkPub(ctx, &ec2.GetInstanceTpmEkPubInput{
		InstanceId: &instanceId,
		KeyType:    types.EkPubKeyTypeRsa2048,
		KeyFormat:  types.EkPubKeyFormatDer,
	})
	if err != nil {
		return nil, fmt.Errorf("GetInstanceTpmEkPub: %w", err)
	}

	if out.KeyValue == nil {
		return nil, fmt.Errorf("response contained no key value")
	}

	der, err := base64.StdEncoding.DecodeString(*out.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("base64-decoding key value: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing DER public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, not *rsa.PublicKey", pub)
	}

	return rsaPub, nil
}
