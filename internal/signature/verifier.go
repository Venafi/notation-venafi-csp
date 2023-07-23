package signature

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/notation-venafi-csp/internal/revoke"
	"github.com/venafi/notation-venafi-csp/internal/signature/jws"
	"github.com/venafi/vsign/pkg/venafi/tpp"
)

func Verify(ctx context.Context, req *proto.VerifySignatureRequest) (*proto.VerifySignatureResponse, error) {
	// TODO validate if PluginConfig is required or can be embedded in signature envelope
	if req == nil {
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

	results := make(map[proto.Capability]*proto.VerificationResult)
	var attr []string

	if url, found := req.Signature.CriticalAttributes.ExtendedAttributes[jws.HeaderVerificationPluginX5U]; found {
		// TPP 23.1+ capability
		_, err := tpp.GetPKSCertificate(url.(string))
		// If x5u exists however TPP no longer manages the lifecycle then fail identity validation
		if err != nil {
			results[proto.CapabilityTrustedIdentityVerifier] = &proto.VerificationResult{
				Success: false,
				//Reason:  "identity validation failed due to missing certificate in CodeSign Protect",
				Reason: err.Error(),
			}
		} else {
			results[proto.CapabilityTrustedIdentityVerifier] = &proto.VerificationResult{
				Success: true,
				Reason:  "Identity validated with x5u extended attribute",
			}
		}
		attr = append(attr, jws.HeaderVerificationPluginX5U)
	} else {
		results[proto.CapabilityTrustedIdentityVerifier] = &proto.VerificationResult{
			Success: true,
			Reason:  "None",
		}
	}

	// Check Revocation status of code signing certificate
	cert, err := x509.ParseCertificate((req.Signature.CertificateChain)[0])
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("error parsing code signing certificate"),
		}
	}

	if revoked, ok := revoke.VerifyCertificate(cert); !ok {
		results[proto.CapabilityRevocationCheckVerifier] = &proto.VerificationResult{
			Success: false,
			Reason:  "soft fail checking revocation.  validate if revocation is functional.",
		}
	} else if !revoked {
		results[proto.CapabilityRevocationCheckVerifier] = &proto.VerificationResult{
			Success: true,
			Reason:  "certificate is valid and not revoked",
		}
	} else if revoked {
		results[proto.CapabilityRevocationCheckVerifier] = &proto.VerificationResult{
			Success: false,
			Reason:  "certificate is revoked",
		}
	}

	processed := make([]interface{}, len(attr))
	for i, s := range attr {
		processed[i] = s
	}

	var verifyResponse = &proto.VerifySignatureResponse{
		VerificationResults: results,
		ProcessedAttributes: processed,
	}

	return verifyResponse, nil

}
