package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"

	"github.com/venafi/notation-venafi-csp/internal/signature"

	"github.com/urfave/cli/v2"
)

var signCommand = &cli.Command{
	Name:   string(plugin.CommandGenerateEnvelope),
	Usage:  "Sign artifacts with keys in Venafi CodeSign Protect",
	Action: runSign,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:      "file",
			Usage:     "request json file",
			TakesFile: true,
			Hidden:    true,
		},
	},
}

func runSign(ctx *cli.Context) error {

	var r io.Reader
	if f := ctx.String("file"); f != "" {
		var err error
		r, err = os.Open(f)
		if err != nil {
			return proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  fmt.Errorf("failed to open reader: %w", err),
			}
		}
	} else {
		r = os.Stdin
	}
	var req plugin.GenerateEnvelopeRequest
	err := json.NewDecoder(r).Decode(&req)
	if err != nil {
		return proto.RequestError{
			Code: plugin.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to unmarshal request input: %w", err),
		}
	}
	resp, err := signature.SignEnvelope(ctx.Context, &req)
	if err != nil {
		var rerr proto.RequestError
		if errors.As(err, &rerr) {
			return rerr
		}
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		return proto.RequestError{
			Code: plugin.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to marshal response: %w", err),
		}
	}

	// write response
	os.Stdout.Write(jsonResp)
	return nil
}
