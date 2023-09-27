package jws

import (
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/vsign/pkg/endpoint"
)

type JWSOptions struct {
	Connector endpoint.Connector
	Env       endpoint.Environment
	Mech      int
	X5u       string
	Req       *proto.GenerateEnvelopeRequest
}
