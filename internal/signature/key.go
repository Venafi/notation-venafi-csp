package signature

import (
	"context"
	"errors"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/vsign/pkg/vsign"
)

func Key(ctx context.Context, req *plugin.DescribeKeyRequest) (*plugin.DescribeKeyResponse, error) {
	if req == nil || req.KeyID == "" {
		return nil, proto.RequestError{
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

	if path, ok := req.PluginConfig["config"]; ok {

		cfg, err := vsign.BuildConfig(ctx, path)
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("error building config"),
			}
		}
		//logger.Log("/Users/ivan.wallis/notation.log", "prior to vsign.NewClient\n")

		connector, err := vsign.NewClient(&cfg)
		//logger.Log("/Users/ivan.wallis/notation.log", err.Error())
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("unable to connect"),
			}
			//fmt.Printf("Unable to connect to %s: %s", cfg.ConnectorType, err)
		} /*else {

			logger.Log("/Users/ivan.wallis/notation.log", "Successfully connected to tpp")
		}*/
		//logger.Log("/Users/ivan.wallis/notation.log", "finish newclient\n")

		keyAlg, err := connector.GetEnvironmentKeyAlgorithm()
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("get environment algorithm error: " + err.Error()),
			}
		}

		keySpec := certToKeySpec(keyAlg)
		if keySpec == "" {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("unrecognized key spec: " + keyAlg),
			}
		}
		return &plugin.DescribeKeyResponse{
			KeyID:   req.KeyID,
			KeySpec: keySpec,
		}, nil
	}

	return nil, proto.RequestError{
		Code: plugin.ErrorCodeValidation,
		Err:  errors.New("unknown describe key request error"),
	}
}

func certToKeySpec(alg string) plugin.KeySpec {
	switch alg {
	case "RSA2048":
		return plugin.KeySpecRSA2048
	case "RSA3072":
		return plugin.KeySpecRSA3072
	case "RSA4096":
		return plugin.KeySpecRSA4096
	case "ECCP256":
		return plugin.KeySpecEC256
	case "ECCP384":
		return plugin.KeySpecEC384
	case "ECCP521":
		return plugin.KeySpecEC521
	}
	return ""
}
