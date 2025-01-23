package jws

import (
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/vsign/pkg/endpoint"
)

type JWSOptions struct {
	Connector endpoint.Connector
	Env       endpoint.Environment
	Mech      int
	X5u       string
	Req       *plugin.GenerateEnvelopeRequest
}
