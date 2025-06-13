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
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/notation-venafi-csp/internal/logger"
	"github.com/venafi/notation-venafi-csp/internal/signature/cose"
	"github.com/venafi/notation-venafi-csp/internal/signature/jws"
	"github.com/venafi/notation-venafi-csp/internal/types"
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
	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tlsConfig
	return nil
}

func SignEnvelope(ctx context.Context, req *plugin.GenerateEnvelopeRequest) (*plugin.GenerateEnvelopeResponse, error) {
	if req == nil || req.KeyID == "" || req.PayloadType == "" || req.SignatureEnvelopeType == "" || len(req.PluginConfig) == 0 {
		for key, value := range req.PluginConfig {
			return nil, logger.Log("notation.log", key+"="+value)
		}
		return nil, &proto.RequestError{
			Code: plugin.ErrorCodeValidation,
			Err:  errors.New("invalid request input"),
		}
	}
	err := setTLSConfig()
	if err != nil {
		return nil, proto.RequestError{
			Code: plugin.ErrorCodeValidation,
			Err:  errors.New("error setting TLS config"),
		}
	}

	//Requires PluginConfig with following key:value format:
	//config=<path.to.config.ini>
	if path, ok := req.PluginConfig["config"]; ok {
		cfg, err := vsign.BuildConfig(ctx, path)
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("error building TPP config"),
			}
		}

		connector, err := vsign.NewClient(&cfg)
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("unable to connect to TPP Server: " + cfg.BaseUrl),
			}

		}

		env, err := connector.GetEnvironment()
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("CSP Get Environment Error: " + err.Error()),
			}
		}

		certs, err := c.ParseCertificates(env.CertificateChainData)
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("certificate parsing error: " + err.Error()),
			}
		}

		mech := certAlgToSigningMethod(certs[0])
		/*if mech == 0 {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("unrecognized signing algorithm"),
			}
		}*/

		var encoded []byte
		var envelopeType string

		// Obtain X5U lookup URL for identity validation during signature verification
		x5u, err := connector.GetJwksX5u(certs[0])
		if err != nil && err != verror.UnSupportedAPI {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("error obtaining jwks x5u"),
			}
		}

		if req.SignatureEnvelopeType == signatureEnvelopeTypeCOSE {
			encoded, err = cose.SignCOSEEnvelope(cose.COSEOptions{Connector: connector, Env: env, Mech: mech, X5u: x5u, Req: req})
			if err != nil {
				return nil, proto.RequestError{
					Code: plugin.ErrorCodeValidation,
					Err:  errors.New("signing error: " + err.Error()),
				}
			}
			envelopeType = signatureEnvelopeTypeCOSE
		} else { // JWS (jose+json)
			encoded, err = jws.SignJWSEnvelope(jws.JWSOptions{Connector: connector, Env: env, Mech: mech, X5u: x5u, Req: req})
			if err != nil {
				return nil, proto.RequestError{
					Code: plugin.ErrorCodeValidation,
					Err:  errors.New("signing error: " + err.Error()),
				}
			}
			envelopeType = signatureEnvelopeTypeJOSE
		}

		var sigEnvelopeResponse = &plugin.GenerateEnvelopeResponse{
			SignatureEnvelope:     encoded,
			SignatureEnvelopeType: envelopeType,
		}

		return sigEnvelopeResponse, nil
	}

	return nil, proto.RequestError{
		Code: plugin.ErrorCodeValidation,
		Err:  errors.New("unknown error during signing operation"),
	}

}

func certAlgToSigningMethod(cert *x509.Certificate) types.SigningMethod {
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return types.SigningMethod{Mechanism: c.EcDsa, KeySize: cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize, Hash: bitSizeToHashAlg(cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize)}
	case *rsa.PublicKey:
		return types.SigningMethod{Mechanism: c.RsaPkcsPss, KeySize: cert.PublicKey.(*rsa.PublicKey).N.BitLen(), Hash: bitSizeToHashAlg(cert.PublicKey.(*rsa.PublicKey).N.BitLen())}
	default:
		return types.SigningMethod{}
	}
}

func bitSizeToHashAlg(bitsize int) string {
	switch bitsize {
	case 256:
		return "sha256"
	case 384:
		return "sha384"
	case 521:
		return "sha512"
	case 2048:
		return "sha256"
	case 3072:
		return "sha384"
	case 4096:
		return "sha512"
	default:
		return "sha256"
	}
}
