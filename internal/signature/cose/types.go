package cose

import (
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/vsign/pkg/endpoint"
)

type COSEOptions struct {
	Connector endpoint.Connector
	Env       endpoint.Environment
	Mech      int
	X5u       string
	Req       *proto.GenerateEnvelopeRequest
}
