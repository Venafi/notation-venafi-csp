package main

import (
	"encoding/json"
	"os"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/notation-venafi-csp/internal/version"

	"github.com/urfave/cli/v2"
)

var metadataCommand = &cli.Command{
	Name:   string(proto.CommandGetMetadata),
	Usage:  "Get plugin metadata",
	Action: runGetMetadata,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:      "file",
			Usage:     "request json file",
			TakesFile: true,
			Hidden:    true,
		},
	},
}

var metadata []byte

func init() {
	var err error
	metadata, err = json.Marshal(proto.GetMetadataResponse{
		Name:                      "venafi-csp",
		Description:               "Sign artifacts with keys in Venafi CodeSign Protect",
		Version:                   version.GetVersion(),
		URL:                       "https://coolsolutions.venafi.com/ivan.wallis/notation-venafi-csp",
		SupportedContractVersions: []string{proto.ContractVersion},
		Capabilities:              []proto.Capability{proto.CapabilitySignatureGenerator},
	})
	if err != nil {
		panic(err)
	}
}

func runGetMetadata(ctx *cli.Context) error {
	// write response
	os.Stdout.Write(metadata)
	return nil
}
