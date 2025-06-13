package signature

import (
	"context"
	"errors"
	"strings"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/notation-venafi-csp/internal/pkix"
	"github.com/venafi/notation-venafi-csp/internal/signature/jws"
	"github.com/venafi/vsign/pkg/venafi/tpp"
)

const (
	trustedIdentitiesType = "x509.subject"
)

func Verify(ctx context.Context, req *plugin.VerifySignatureRequest) (*plugin.VerifySignatureResponse, error) {
	// TODO validate if PluginConfig is required or can be embedded in signature envelope
	if req == nil {
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

	results := make(map[plugin.Capability]*plugin.VerificationResult)
	var attr []string

	if url, found := req.Signature.CriticalAttributes.ExtendedAttributes[jws.HeaderVerificationPluginX5U]; found {
		// TPP 23.1+ capability
		leaf, err := tpp.GetPKSCertificate(url.(string))
		// If x5u exists however TPP no longer manages the lifecycle then fail identity validation
		if err != nil {
			results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
				Success: false,
				//Reason:  "identity validation failed due to missing certificate in CodeSign Protect",
				Reason: err.Error(),
			}
		} else {
			var trustedX509Identities []map[string]string
			for _, identity := range req.TrustPolicy.TrustedIdentities {
				identityPrefix, identityValue, _ := strings.Cut(identity, ":")
				if identityPrefix == trustedIdentitiesType {
					parsedSubject, err := pkix.ParseDistinguishedName(identityValue)
					if err != nil {
						return nil, proto.RequestError{
							Code: plugin.ErrorCodeValidation,
							Err:  errors.New("error parsing X.509 certificate subject"),
						}
					}
					trustedX509Identities = append(trustedX509Identities, parsedSubject)
				}

			}

			leafCertDN, err := pkix.ParseDistinguishedName(leaf.Subject.String())
			if err != nil {
				return nil, proto.RequestError{
					Code: plugin.ErrorCodeValidation,
					Err:  errors.New("error while parsing the certificate subject from the digital signature"),
				}
			}
			for _, trustedX509Identity := range trustedX509Identities {
				if pkix.IsSubsetDN(trustedX509Identity, leafCertDN) {
					results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
						Success: true,
						Reason:  "Identity validated with x5u extended attribute",
					}
					break
				}
			}

			// Assume trustedIdentities configured as wildcard
			if len(trustedX509Identities) == 0 {
				results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
					Success: true,
					Reason:  "Identity validated with x5u extended attribute.  TrustedIdentities configured with wildcard policy.",
				}
			}

			if _, ok := results[plugin.CapabilityTrustedIdentityVerifier]; !ok {
				results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
					Success: false,
					Reason:  "Signing certificate from digital signature does not match x.509 trusted identities defined in the trust policy",
				}
			}

		}
		attr = append(attr, jws.HeaderVerificationPluginX5U)
	} else {
		// Venafi TPP 23.1+ and venafi notation plugin 0.2+
		results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
			Success: false,
			Reason:  "Trusted Identity verification requires TPP 23.1+ and plugin 0.2+",
		}
	}

	processed := make([]interface{}, len(attr))
	for i, s := range attr {
		processed[i] = s
	}

	var verifyResponse = &plugin.VerifySignatureResponse{
		VerificationResults: results,
		ProcessedAttributes: processed,
	}

	return verifyResponse, nil

}
