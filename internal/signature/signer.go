package signature

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	// Make required hashers available.

	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/tls"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/notation-venafi-csp/internal/logger"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"
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
			DigestAlg: "sha256",
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

		// Load ZTPKI Root
		/*r, _ := ioutil.ReadFile("/Users/ivan.wallis/notation-venafi-csp/test/ztpkiroot.crt")
		block, _ := pem.Decode(r)

		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, plugin.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("invalid certificate"),
			}
		}

		r, _ = ioutil.ReadFile("/Users/ivan.wallis/notation-venafi-csp/test/ztpkiissuer.crt")
		block, _ = pem.Decode(r)

		ica, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, plugin.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("invalid certificate"),
			}
		}*/

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
			//CertificateChain: [][]byte{env.Certificate.Raw},
			//CertificateChain: [][]byte{env.Certificate.Raw, ica.Raw, root.Raw},
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
