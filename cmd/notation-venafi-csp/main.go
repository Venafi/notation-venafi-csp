package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/venafi/notation-venafi-csp/internal/version"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "notation-venafi-csp",
		Usage: "Notation - Notary V2 Venafi CodeSign Protect plugin",
		// TODO(zosocanuck) add version package
		Version: version.GetVersion(),
		Commands: []*cli.Command{
			metadataCommand,
			signCommand,
			verifyCommand,
			describeKeyCommand,
		},
	}
	if err := app.Run(os.Args); err != nil {
		var reer proto.RequestError
		if !errors.As(err, &reer) {
			err = proto.RequestError{
				Code: proto.ErrorCodeGeneric,
				Err:  err,
			}
		}
		data, _ := json.Marshal(err)
		os.Stderr.Write(data)
		os.Exit(1)
	}
}
