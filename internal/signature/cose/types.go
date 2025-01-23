package cose

import (
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/vsign/pkg/endpoint"
)

type COSEOptions struct {
	Connector endpoint.Connector
	Env       endpoint.Environment
	Mech      int
	X5u       string
	Req       *plugin.GenerateEnvelopeRequest
}
