package signature

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
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

// validateX5UURL validates that the x5u URL is safe to request:
// 1. It must match the configured Venafi CSP endpoint
// 2. It must not resolve to RFC-1918, loopback, or link-local addresses
func validateX5UURL(x5uURL, baseURL string) error {
	// Parse the x5u URL
	parsedX5U, err := url.Parse(x5uURL)
	if err != nil {
		return fmt.Errorf("invalid x5u URL: %w", err)
	}

	// Parse the base URL
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}

	// Validate scheme is HTTPS
	if parsedX5U.Scheme != "https" {
		return errors.New("x5u URL must use HTTPS")
	}

	// Validate that x5u URL host matches the configured endpoint
	if parsedX5U.Host != parsedBase.Host {
		return fmt.Errorf("x5u URL host %q does not match configured endpoint %q", parsedX5U.Host, parsedBase.Host)
	}

	// Resolve the hostname to check for private addresses
	host := parsedX5U.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve x5u URL host: %w", err)
	}

	// Check each resolved IP for private/internal ranges
	for _, ip := range ips {
		// Block loopback addresses (127.0.0.0/8, ::1)
		if ip.IsLoopback() {
			return fmt.Errorf("x5u URL resolves to loopback address: %s", ip)
		}

		// Block link-local addresses (169.254.0.0/16, fe80::/10)
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("x5u URL resolves to link-local address: %s", ip)
		}

		// Block private addresses (RFC-1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
		if ip.IsPrivate() {
			return fmt.Errorf("x5u URL resolves to private address: %s", ip)
		}
	}

	return nil
}

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

	// Get the configured base URL for validation
	var baseURL string
	if path, ok := req.PluginConfig["config"]; ok {
		cfg, err := vsign.BuildConfig(ctx, path)
		if err != nil {
			return nil, proto.RequestError{
				Code: plugin.ErrorCodeValidation,
				Err:  errors.New("error building TPP config"),
			}
		}
		baseURL = cfg.BaseUrl
	}

	results := make(map[plugin.Capability]*plugin.VerificationResult)
	var attr []string

	if x5uAttr, found := req.Signature.CriticalAttributes.ExtendedAttributes[jws.HeaderVerificationPluginX5U]; found {
		// TPP 23.1+ capability
		x5uURL := x5uAttr.(string)

		// Validate x5u URL before making request
		if baseURL != "" {
			if err := validateX5UURL(x5uURL, baseURL); err != nil {
				results[plugin.CapabilityTrustedIdentityVerifier] = &plugin.VerificationResult{
					Success: false,
					Reason:  fmt.Sprintf("x5u URL validation failed: %v", err),
				}
				processed := make([]interface{}, len(attr))
				for i, s := range attr {
					processed[i] = s
				}
				return &plugin.VerifySignatureResponse{
					VerificationResults: results,
					ProcessedAttributes: processed,
				}, nil
			}
		}

		_, err := tpp.GetPKSCertificate(x5uURL)
		// If x5u exists however TPP no longer manages the lifecycle then fail identity validation
		if err != nil {
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
