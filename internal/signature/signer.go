package signature

import (
	"context"
	"errors"
	"net/http"

	// Make required hashers available.

	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/notation-venafi-csp/internal/logger"
	"github.com/venafi/notation-venafi-csp/internal/signature/cose"
	"github.com/venafi/notation-venafi-csp/internal/signature/jws"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/verror"
	"github.com/venafi/vsign/pkg/vsign"
)

const (
	MediaTypePayloadV1        = "application/vnd.cncf.notary.payload.v1+json"
	signatureEnvelopeTypeJOSE = "application/jose+json"
	signatureEnvelopeTypeCOSE = "application/cose"
)

var (
	tlsConfig tls.Config
)

func setTLSConfig() error {
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig
	return nil
}

func SignEnvelope(ctx context.Context, req *proto.GenerateEnvelopeRequest) (*proto.GenerateEnvelopeResponse, error) {
	if req == nil || req.KeyID == "" || req.PayloadType == "" || req.SignatureEnvelopeType == "" || len(req.PluginConfig) == 0 {
		for key, value := range req.PluginConfig {
			return nil, logger.Log("notation.log", key+"="+value)
		}
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("invalid request input"),
		}
	}

	err := setTLSConfig()
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("error setting TLS config"),
		}
	}

	//Requires PluginConfig with following key:value format:
	//config=<path.to.config.ini>
	if path, ok := req.PluginConfig["config"]; ok {
		cfg, err := vsign.BuildConfig(ctx, path)
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("error building TPP config"),
			}
		}

		connector, err := vsign.NewClient(&cfg)
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("unable to connect to TPP Server: " + cfg.BaseUrl),
			}

		}

		env, err := connector.GetEnvironment()
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("CSP Get Environment Error: " + err.Error()),
			}
		}

		certs, err := c.ParseCertificates(env.CertificateChainData)
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("certificate parsing error: " + err.Error()),
			}
		}

		mech := certAlgToMech(certs[0])
		if mech == 0 {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("unrecognized signing algorithm"),
			}
		}

		var encoded []byte
		var envelopeType string

		// Obtain X5U lookup URL for identity validation during signature verification
		x5u, err := connector.GetJwksX5u(certs[0])
		if err != nil && err != verror.UnSupportedAPI {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("error obtaining jwks x5u"),
			}
		}

		if req.SignatureEnvelopeType == signatureEnvelopeTypeCOSE {
			encoded, err = cose.SignCOSEEnvelope(cose.COSEOptions{Connector: connector, Env: env, Mech: mech, X5u: x5u, Req: req})
			if err != nil {
				return nil, proto.RequestError{
					Code: proto.ErrorCodeValidation,
					Err:  errors.New("signing error: " + err.Error()),
				}
			}
			envelopeType = signatureEnvelopeTypeCOSE
		} else { // JWS (jose+json)
			encoded, err = jws.SignJWSEnvelope(jws.JWSOptions{Connector: connector, Env: env, Mech: mech, X5u: x5u, Req: req})
			if err != nil {
				return nil, proto.RequestError{
					Code: proto.ErrorCodeValidation,
					Err:  errors.New("signing error: " + err.Error()),
				}
			}
			envelopeType = signatureEnvelopeTypeJOSE
		}

		var sigEnvelopeResponse = &proto.GenerateEnvelopeResponse{
			SignatureEnvelope:     encoded,
			SignatureEnvelopeType: envelopeType,
		}

		return sigEnvelopeResponse, nil
	}

	return nil, proto.RequestError{
		Code: proto.ErrorCodeValidation,
		Err:  errors.New("error during signing operation: " + err.Error()),
	}
}

func certAlgToMech(cert *x509.Certificate) int {
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return c.EcDsa
	case *rsa.PublicKey:
		return c.RsaPkcsPss
	default:
		return 0
	}
}
