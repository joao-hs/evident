// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	stdlog "log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/terraform/provider"
)

var (
	// these will be set by the goreleaser configuration
	// to appropriate values for the compiled binary.
	version string = "dev"

	// goreleaser can pass other information to the main package, such as the specific commit
	// https://goreleaser.com/cookbooks/using-main.version/
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/dpss-inesc-id/evident",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)

	if err != nil {
		stdlog.Fatal(err.Error())
	}
}

func setupLogger(debug bool) error {
	dot := dotevident.Get()
	logFilePath := dot.GetLogFilePath("tf-provider")
	err := log.GetLogFileSyncer().Swap(logFilePath)
	if err != nil {
		return err
	}
	if debug {
		log.Get().SetDebugLevel()
	}
	return nil
}
