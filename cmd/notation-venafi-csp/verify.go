package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/urfave/cli/v2"
	"github.com/venafi/notation-venafi-csp/internal/signature"
)

var verifyCommand = &cli.Command{
	Name:   string(proto.CommandVerifySignature),
	Usage:  "Verifies artifact signatures produced by Venafi CodeSign Protect",
	Action: runVerify,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:      "file",
			Usage:     "request json file",
			TakesFile: true,
			Hidden:    true,
		},
	},
}

func runVerify(ctx *cli.Context) error {

	var r io.Reader
	if f := ctx.String("file"); f != "" {
		var err error
		r, err = os.Open(f)
		if err != nil {
			return proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  fmt.Errorf("failed to open reader: %w", err),
			}
		}
	} else {
		r = os.Stdin
	}
	var req proto.VerifySignatureRequest
	err := json.NewDecoder(r).Decode(&req)
	if err != nil {
		return proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to unmarshal request input: %w", err),
		}
	}
	resp, err := signature.Verify(ctx.Context, &req)
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
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to marshal response: %w", err),
		}
	}

	// write response
	os.Stdout.Write(jsonResp)
	return nil
}
