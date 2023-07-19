package signature

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	// Make required hashers available.

	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"

	"github.com/golang-jwt/jwt/v5"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/notation-venafi-csp/internal/logger"
	"github.com/venafi/notation-venafi-csp/internal/signature/jws"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"
)

const (
	MediaTypePayloadV1        = "application/vnd.cncf.notary.payload.v1+json"
	signatureEnvelopeTypeJOSE = "application/jose+json"
	signatureEnvelopeTypeCOSE = "application/cose"
	defaultDigestAlg          = "sha256"
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

	// TODO implement signature envelope type
	if req.SignatureEnvelopeType == "cose" {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("unsupported signature envelope type"),
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

		mech, jwtAlg := certAlgToMech(certs[0])
		if mech == 0 {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("unrecognized signing algorithm"),
			}
		}

		// Generate extended attributes
		ext := jws.GenerateExtendedAttributes()

		// get all attributes ready to be signed
		signedAttrs, err := jws.GetSignedAttributes(ext, jwtAlg)
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("payload unmarshal error: " + err.Error()),
			}
		}

		// parse payload as jwt.MapClaims
		// [jwt-go]: https://pkg.go.dev/github.com/dgrijalva/jwt-go#MapClaims
		var payload jwt.MapClaims
		if err = json.Unmarshal(req.Payload, &payload); err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("payload format error: %v" + err.Error()),
			}
		}

		// generate token
		token := jwt.NewWithClaims(jwt.GetSigningMethod(jwtAlg), payload)
		token.Header = signedAttrs

		var sstr string

		if sstr, err = token.SigningString(); err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("jwt signing string error: %v" + err.Error()),
			}
		}

		sig, err := connector.Sign(&endpoint.SignOption{
			KeyID:     env.KeyID,
			Mechanism: mech,
			DigestAlg: defaultDigestAlg,
			Payload:   []byte(sstr),
			B64Flag:   false,
			RawFlag:   false,
		})

		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("signing error: " + err.Error()),
			}
		}

		compact := strings.Join([]string{sstr, base64.RawURLEncoding.EncodeToString(sig)}, ".")

		tsrRsp, err := jws.GenerateRFC3161TimeStampSignature(sig)
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("timestamping error: " + err.Error()),
			}
		}

		// generate envelope
		envelope, err := jws.GenerateJWS(compact, certs, tsrRsp)
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("invalid signature error: %v" + err.Error()),
			}
		}

		encoded, err := json.Marshal(envelope)
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("invalid json encoding error: %v" + err.Error()),
			}
		}

		//dec, err := base64.StdEncoding.DecodeString(string(encoded))

		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("base64 decoding error: " + err.Error() + "[" + string(encoded) + "]"),
			}
		}

		//newSig, _ := base64.RawURLEncoding.DecodeString(base64.RawURLEncoding.EncodeToString(dec))

		var sigEnvelopeResponse = &proto.GenerateEnvelopeResponse{
			//SignatureEnvelope:     newSig,
			SignatureEnvelope:     encoded,
			SignatureEnvelopeType: signatureEnvelopeTypeJOSE,
		}

		return sigEnvelopeResponse, nil
	}

	return nil, proto.RequestError{
		Code: proto.ErrorCodeValidation,
		Err:  errors.New("error during signing operation: " + err.Error()),
	}
}

func Sign(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	if req == nil || req.KeyID == "" || req.KeySpec == "" || req.Hash == "" || len(req.PluginConfig) == 0 {
		for key, value := range req.PluginConfig {
			return nil, logger.Log("notation.log", key+"="+value)
		}
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("invalid request input"),
		}
	}

	// get keySpec
	keySpec, err := proto.DecodeKeySpec(req.KeySpec)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("parse key spec error: " + err.Error()),
		}
	}

	err = setTLSConfig()
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

		mech := keySpecToAlg(req.KeySpec)
		if mech == 0 {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("unrecognized key spec: " + string(req.KeySpec)),
			}
		}
		//sig, err := connector.Sign(env.KeyID, mech, "sha256", string(req.Payload), false, true)
		sig, err := connector.Sign(&endpoint.SignOption{
			KeyID:     env.KeyID,
			Mechanism: mech,
			DigestAlg: defaultDigestAlg,
			Payload:   req.Payload,
			B64Flag:   false,
			RawFlag:   true,
		})

		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("signing error: " + err.Error()),
			}
		}

		dec, err := base64.StdEncoding.DecodeString(string(sig))

		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("base64 decoding error: " + err.Error()),
			}
		}

		newSig, _ := base64.RawURLEncoding.DecodeString(base64.RawURLEncoding.EncodeToString(dec))

		sigAlg, err := proto.EncodeSigningAlgorithm(keySpec.SignatureAlgorithm())
		if err != nil {
			return nil, proto.RequestError{
				Code: proto.ErrorCodeValidation,
				Err:  errors.New("error encoding signing algorithm: " + err.Error()),
			}
		}

		var sigResponse = &proto.GenerateSignatureResponse{
			KeyID:            req.KeyID,
			Signature:        newSig,
			SigningAlgorithm: string(sigAlg),
			CertificateChain: env.CertificateChainData,
		}

		return sigResponse, nil
	}

	return nil, proto.RequestError{
		Code: proto.ErrorCodeValidation,
		Err:  errors.New("error during signing operation: " + err.Error()),
	}

}

func keySpecToAlg(k proto.KeySpec) int {
	switch k {
	case proto.KeySpecRSA2048, proto.KeySpecRSA3072, proto.KeySpecRSA4096:
		return c.RsaPkcsPss
	case proto.KeySpecEC256, proto.KeySpecEC384, proto.KeySpecEC521:
		return c.EcDsa
	}
	return 0
}

func certAlgToMech(cert *x509.Certificate) (int, string) {
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return c.EcDsa, "ES256"
	case *rsa.PublicKey:
		return c.RsaPkcsPss, "PS256"
	default:
		return 0, ""
	}
}
