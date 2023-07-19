package signature

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/notation-venafi-csp/internal/revoke"
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
	results[proto.CapabilityTrustedIdentityVerifier] = &proto.VerificationResult{
		Success: true,
		Reason:  "None",
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

	var verifyResponse = &proto.VerifySignatureResponse{
		VerificationResults: results,
		ProcessedAttributes: nil,
	}

	return verifyResponse, nil

}
