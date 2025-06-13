package jws

import (
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/notation-venafi-csp/internal/types"
	"github.com/venafi/vsign/pkg/endpoint"
)

type JWSOptions struct {
	Connector endpoint.Connector
	Env       endpoint.Environment
	Mech      types.SigningMethod
	X5u       string
	Req       *plugin.GenerateEnvelopeRequest
}
