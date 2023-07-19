package jws

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/venafi/notation-venafi-csp/internal/version"
)

const (
	mediaTypePayloadV1                 = "application/vnd.cncf.notary.payload.v1+json"
	headerKeyExpiry                    = "io.cncf.notary.expiry"
	headerKeySigningScheme             = "io.cncf.notary.signingScheme"
	headerKeyAuthenticSigningTime      = "io.cncf.notary.authenticSigningTime"
	headerTimeStampSignature           = "io.cncf.notary.timestampSignature"
	headerVerificationPlugin           = "io.cncf.notary.verificationPlugin"
	headerVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
	headerVerificationPluginX5U        = "com.venafi.notation.plugin.x5u"
)

// jwsUnprotectedHeader contains the set of unprotected headers.
type jwsUnprotectedHeader struct {
	// RFC3161 time stamp token Base64-encoded.
	TimestampSignature []byte `json:"io.cncf.notary.timestampSignature,omitempty"`

	// List of X.509 Base64-DER-encoded certificates
	// as defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
	CertChain [][]byte `json:"x5c"`

	// SigningAgent used for signing.
	SigningAgent string `json:"io.cncf.notary.signingAgent,omitempty"`
}

// jwsProtectedHeader contains the set of protected headers.
type jwsProtectedHeader struct {
	// Defines which algorithm was used to generate the signature.
	Algorithm string `json:"alg"`

	// Media type of the secured content (the payload).
	ContentType string `json:"cty"`

	// Lists the headers that implementation MUST understand and process.
	Critical []string `json:"crit,omitempty"`

	// The "best by use" time for the artifact, as defined by the signer.
	Expiry *time.Time `json:"io.cncf.notary.expiry,omitempty"`

	// Specifies the Notary Project Signing Scheme used by the signature.
	SigningScheme signature.SigningScheme `json:"io.cncf.notary.signingScheme"`

	// The time at which the signature was generated. only valid when signing
	// scheme is `notary.x509`.
	SigningTime *time.Time `json:"io.cncf.notary.signingTime,omitempty"`

	// The time at which the signature was generated. only valid when signing
	// scheme is `notary.x509.signingAuthority`.
	AuthenticSigningTime *time.Time `json:"io.cncf.notary.authenticSigningTime,omitempty"`

	// The user defined attributes.
	ExtendedAttributes map[string]interface{} `json:"-"`
}

// jwsEnvelope is the final Signature envelope.
type jwsEnvelope struct {
	// JWSPayload Base64URL-encoded. Raw data should be JSON format.
	Payload string `json:"payload"`

	// jwsProtectedHeader Base64URL-encoded.
	Protected string `json:"protected"`

	// Signature metadata that is not integrity Protected
	Header jwsUnprotectedHeader `json:"header"`

	// Base64URL-encoded Signature.
	Signature string `json:"signature"`
}

func GenerateExtendedAttributes() []signature.Attribute {
	// Need extended protected headers for plugin signature envelope verification
	var ext []signature.Attribute
	ext = append(ext, signature.Attribute{Key: headerVerificationPlugin, Value: version.PluginName, Critical: true})
	ext = append(ext, signature.Attribute{Key: headerVerificationPluginMinVersion, Value: version.GetVersion(), Critical: true})
	// Test custom extended attribute
	//ext = append(ext, signature.Attribute{Key: headerTimeStampSignature, Value: timestamp, Critical: true})
	ext = append(ext, signature.Attribute{Key: "venafi-custom-attribute", Value: "test", Critical: false})

	return ext
}

func GenerateRFC3161TimeStampSignature(sig []byte) ([]byte, error) {

	tsq, err := timestamp.CreateRequest(bytes.NewReader(sig), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		return nil, err
	}

	tsr, err := http.Post("https://freetsa.org/tsr", "application/timestamp-query", bytes.NewReader(tsq))
	if err != nil {
		return nil, err
	}

	if tsr.StatusCode > 200 {
		return nil, err
	}

	resp, err := io.ReadAll(tsr.Body)
	if err != nil {
		return nil, err
	}

	// Make sure it is valid timestamp signature
	_, err = timestamp.ParseResponse(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func GenerateJWS(compact string, certs []*x509.Certificate, tsrRsp []byte) (*jwsEnvelope, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		// this should never happen
		return nil, fmt.Errorf(
			"unexpected error occurred while generating a JWS-JSON serialization from compact serialization. want: len(parts) == 3, got: len(parts) == %d", len(parts))
	}

	rawCerts := make([][]byte, len(certs))
	for i, cert := range certs {
		rawCerts[i] = cert.Raw
	}

	return &jwsEnvelope{
		Protected: parts[0],
		Payload:   parts[1],
		Signature: parts[2],
		Header: jwsUnprotectedHeader{
			TimestampSignature: tsrRsp,
			CertChain:          rawCerts,
			SigningAgent:       version.SigningAgent,
		},
	}, nil
}

// getSignerAttributes merge extended signed attributes and protected header to be signed attributes.
func GetSignedAttributes(extendedAttributes []signature.Attribute, algorithm string) (map[string]interface{}, error) {
	extAttrs := make(map[string]interface{})
	crit := []string{headerKeySigningScheme}

	// write extended signed attributes to the extAttrs map
	for _, elm := range extendedAttributes {
		key, ok := elm.Key.(string)
		if !ok {
			return nil, fmt.Errorf("jws envelope format only supports key of type string")
		}
		if _, ok := extAttrs[key]; ok {
			return nil, fmt.Errorf("%q already exists in the extAttrs", key)
		}
		extAttrs[key] = elm.Value
		if elm.Critical {
			crit = append(crit, key)
		}
	}

	jwsProtectedHeader := jwsProtectedHeader{
		Algorithm:     algorithm,
		ContentType:   mediaTypePayloadV1,
		SigningScheme: signature.SigningSchemeX509,
	}

	/*switch req.SigningScheme {
	case signature.SigningSchemeX509:
		jwsProtectedHeader.SigningTime = &req.SigningTime
	case signature.SigningSchemeX509SigningAuthority:
		crit = append(crit, headerKeyAuthenticSigningTime)
		jwsProtectedHeader.AuthenticSigningTime = &req.SigningTime
	default:
		return nil, fmt.Errorf("unsupported SigningScheme: `%v`", req.SigningScheme)
	}*/
	// TODO Testing purposes only
	t := time.Now()
	jwsProtectedHeader.SigningTime = &t

	// TODO
	/*if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
		jwsProtectedHeader.Expiry = &req.Expiry
	}*/

	jwsProtectedHeader.Critical = crit
	m, err := convertToMap(jwsProtectedHeader)
	if err != nil {
		return nil, fmt.Errorf("unexpected error occurred while creating protected headers, Error: %s", err.Error())
	}

	return mergeMaps(m, extAttrs)
}

func convertToMap(i interface{}) (map[string]interface{}, error) {
	s, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	err = json.Unmarshal(s, &m)
	return m, err
}

func mergeMaps(maps ...map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			if _, ok := result[k]; ok {
				return nil, fmt.Errorf("attribute key:%s repeated", k)
			}
			result[k] = v
		}
	}
	return result, nil
}
