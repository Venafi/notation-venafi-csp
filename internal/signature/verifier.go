package signature

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"github.com/venafi/notation-venafi-csp/internal/pkix"
	"github.com/venafi/notation-venafi-csp/internal/signature/jws"
	"github.com/venafi/vsign/pkg/venafi/tpp"
	"github.com/venafi/vsign/pkg/vsign"
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

	if x5uAttr, found := req.Signature.CriticalAttributes.ExtendedAttributes[jws.HeaderVerificationPluginX5U]; found {
		// TPP 23.1+ capability
		x5uURL, ok := x5uAttr.(string)
		if !ok {
			results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
				Success: false,
				Reason:  "x5u attribute is not a string",
			}
		} else {
			// Validate x5u URL scheme and host
			parsed, err := url.Parse(x5uURL)
			if err != nil {
				results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
					Success: false,
					Reason:  "x5u URL parsing failed: " + err.Error(),
				}
			} else if parsed.Scheme != "https" {
				results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
					Success: false,
					Reason:  "x5u URL must use HTTPS scheme",
				}
			} else {
				// Validate x5u host matches configured TPP host
				var tppHost string
				if configPath, ok := req.PluginConfig["config"]; ok {
					cfg, err := vsign.BuildConfig(ctx, configPath)
					if err == nil {
						baseURL, err := url.Parse(cfg.BaseUrl)
						if err == nil {
							tppHost = baseURL.Host
						}
					}
				}
				if tppHost == "" {
					results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
						Success: false,
						Reason:  "x5u validation requires pluginConfig[config] to verify TPP host",
					}
				} else if parsed.Host != tppHost {
					results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
						Success: false,
						Reason:  "x5u URL host does not match configured TPP host",
					}
				} else {
					// Fetch certificate from validated x5u URL
					leaf, err := tpp.GetPKSCertificate(x5uURL)
					// If x5u exists however TPP no longer manages the lifecycle then fail identity validation
					if err != nil {
						results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
							Success: false,
							//Reason:  "identity validation failed due to missing certificate in CodeSign Protect",
							Reason: err.Error(),
						}
					} else {
						// Bind x5u certificate to envelope signing certificate by comparing public keys
						if len(req.Signature.CertificateChain) == 0 {
							results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
								Success: false,
								Reason:  "signature certificateChain is empty",
							}
						} else if signerCert, perr := x509.ParseCertificate(req.Signature.CertificateChain[0]); perr != nil {
							results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
								Success: false,
								Reason:  "error parsing signature certificateChain leaf",
							}
						} else if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, signerCert.RawSubjectPublicKeyInfo) {
							results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
								Success: false,
								Reason:  "x5u certificate public key does not match signature certificateChain leaf",
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
					}
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
