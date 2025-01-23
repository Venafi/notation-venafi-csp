package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/notation-venafi-csp/internal/signature"

	"github.com/urfave/cli/v2"
)

var describeKeyCommand = &cli.Command{
	Name:   string(plugin.CommandDescribeKey),
	Usage:  "CodeSign Protect key description",
	Action: runDescribeKey,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:      "file",
			Usage:     "request json file",
			TakesFile: true,
			Hidden:    true,
		},
	},
}

func runDescribeKey(ctx *cli.Context) error {
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
	var req plugin.DescribeKeyRequest
	err := json.NewDecoder(r).Decode(&req)
	if err != nil {
		return proto.RequestError{
			Code: plugin.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to unmarshal request input: %w", err),
		}
	}

	resp, err := signature.Key(ctx.Context, &req)
	if err != nil {
		return proto.RequestError{
			Code: plugin.ErrorCodeValidation,
			Err:  fmt.Errorf("describe-key error: %w", err),
		}
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
