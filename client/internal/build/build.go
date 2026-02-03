package build

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type VMImageBuilder interface {
	BuildImage(flakePath string, variation string, imageOutputPath string) error
	ShowBuildImageCommands(flakePath string, variation string, imageOutputPath string)
}

type vmImageBuilder struct {
	nixCmd string
	cpCmd  string
}

const (
	_NIX                      = "nix"
	_CP                       = "cp"
	_NIX_RESULT_PATH          = "/tmp/evident"
	_NIX_RESULT_VM_IMAGE_PATH = "/tmp/evident/disk.raw"
)

func NewVMImageBuilder() (VMImageBuilder, error) {
	self := &vmImageBuilder{
		nixCmd: "",
		cpCmd:  "",
	}

	if err := self.checkRequiredExternalCommands(); err != nil {
		return nil, err
	}

	return self, nil
}

func (self *vmImageBuilder) checkRequiredExternalCommands() error {
	var err error

	self.nixCmd, err = exec.LookPath(_NIX)
	if err != nil {
		return fmt.Errorf("`nix` command is not present in PATH")
	}
	log.Get().Debugf("nix command found at: %s", self.nixCmd)

	self.cpCmd, err = exec.LookPath(_CP)
	if err != nil {
		return fmt.Errorf("`cp` command is not present in PATH")
	}
	log.Get().Debugf("cp command found at: %s", self.cpCmd)

	return nil
}

// BuildImage builds a VM image from a Nix flake and stores it at imageOutputPath
// flakePath: absolute path to the Nix flake directory
// variation: variation inside the Nix flake to build
// imageOutputPath: absolute path where to store the built VM image
func (self *vmImageBuilder) BuildImage(flakePath string, variation string, imageOutputPath string) error {
	var (
		err      error
		buildOut bytes.Buffer
		buildErr bytes.Buffer
	)
	log.Get().Debugln("Running:", self.nixCmd, "build", fmt.Sprintf("%s#%s", flakePath, variation), "-o", _NIX_RESULT_PATH)
	buildCmd := exec.Command(self.nixCmd, "build", fmt.Sprintf("%s#%s", flakePath, variation), "-o", _NIX_RESULT_PATH)

	buildCmd.Stdout = &buildOut
	buildCmd.Stderr = &buildErr

	err = buildCmd.Run()
	if err != nil {
		return fmt.Errorf("nix build failed: %s: %s", err.Error(), buildErr.String())
	}

	resultVmImage, err := filepath.Abs(_NIX_RESULT_VM_IMAGE_PATH)
	if err != nil {
		return fmt.Errorf("could not determine absolute path of built VM image: %s", err.Error())
	}

	log.Get().Debugln("Running:", self.cpCmd, resultVmImage, imageOutputPath)
	cpCmd := exec.Command(self.cpCmd, resultVmImage, imageOutputPath)
	err = cpCmd.Run()
	if err != nil {
		return fmt.Errorf("copying built VM image failed: %s", err.Error())
	}

	return nil
}

func (self *vmImageBuilder) ShowBuildImageCommands(flakePath string, variation string, imageOutputPath string) {
	fmt.Printf("%s build %s#%s -o %s && \\\n", self.nixCmd, flakePath, variation, _NIX_RESULT_PATH)
	fmt.Printf("%s %s %s\n", self.cpCmd, _NIX_RESULT_VM_IMAGE_PATH, imageOutputPath)
}
