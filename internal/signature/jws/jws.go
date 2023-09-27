package jws

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/venafi/notation-venafi-csp/internal/version"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
)

const (
	mediaTypePayloadV1                 = "application/vnd.cncf.notary.payload.v1+json"
	headerKeyExpiry                    = "io.cncf.notary.expiry"
	headerKeySigningScheme             = "io.cncf.notary.signingScheme"
	headerKeyAuthenticSigningTime      = "io.cncf.notary.authenticSigningTime"
	headerTimeStampSignature           = "io.cncf.notary.timestampSignature"
	headerVerificationPlugin           = "io.cncf.notary.verificationPlugin"
	headerVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
	HeaderVerificationPluginX5U        = "com.venafi.notation.plugin.x5u"
	defaultDigestAlg                   = "sha256"
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

func SignJWSEnvelope(jwsOpts JWSOptions) ([]byte, error) {
	// Generate extended attributes
	ext := GenerateExtendedAttributes(jwsOpts.X5u)

	jwtAlg := certAlgToJWTAlg(jwsOpts.Mech)
	// get all attributes ready to be signed
	signedAttrs, err := getSignedAttributes(ext, jwtAlg)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("payload unmarshal error: " + err.Error()),
		}
	}

	// parse payload as jwt.MapClaims
	// [jwt-go]: https://pkg.go.dev/github.com/dgrijalva/jwt-go#MapClaims
	var payload jwt.MapClaims
	if err = json.Unmarshal(jwsOpts.Req.Payload, &payload); err != nil {
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

	sig, err := jwsOpts.Connector.Sign(&endpoint.SignOption{
		KeyID:     jwsOpts.Env.KeyID,
		Mechanism: jwsOpts.Mech,
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

	// TODO need RFC3161 support within notation cli
	/*tsrRsp, err := jws.GenerateRFC3161TimeStampSignature(sig)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("timestamping error: " + err.Error()),
		}
	}*/

	certs, err := c.ParseCertificates(jwsOpts.Env.CertificateChainData)
	if err != nil {
		return nil, err
	}

	// generate envelope
	// envelope, err := jws.GenerateJWS(compact, certs, tsrRsp)
	envelope, err := generateJWS(compact, certs)
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

	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("base64 decoding error: " + err.Error() + "[" + string(encoded) + "]"),
		}
	}

	return encoded, nil

}

func GenerateExtendedAttributes(x5u string) []signature.Attribute {
	// Need extended protected headers for plugin signature envelope verification
	var ext []signature.Attribute
	ext = append(ext, signature.Attribute{Key: headerVerificationPlugin, Value: version.PluginName, Critical: true})
	ext = append(ext, signature.Attribute{Key: headerVerificationPluginMinVersion, Value: version.GetVersion(), Critical: true})
	// Test custom extended attribute
	//ext = append(ext, signature.Attribute{Key: headerTimeStampSignature, Value: timestamp, Critical: true})
	if x5u != "" {
		// Add JWKS X5U attribute for identity validation during envelope signature verification.
		// Requires TPP 23.1+
		ext = append(ext, signature.Attribute{Key: HeaderVerificationPluginX5U, Value: x5u, Critical: false})
	}
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

func generateJWS(compact string, certs []*x509.Certificate) (*jwsEnvelope, error) {

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
			//TimestampSignature: tsrRsp,
			CertChain:    rawCerts,
			SigningAgent: version.SigningAgent,
		},
	}, nil
}

// getSignerAttributes merge extended signed attributes and protected header to be signed attributes.
func getSignedAttributes(extendedAttributes []signature.Attribute, algorithm string) (map[string]interface{}, error) {
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

	// Currently plugin only supports the x.509 Signing Scheme -> notary.x509
	jwsProtectedHeader := jwsProtectedHeader{
		Algorithm:     algorithm,
		ContentType:   mediaTypePayloadV1,
		SigningScheme: signature.SigningSchemeX509,
	}

	// TODO Need to eventually move to signingAuthority scheme with CSP as trusted service for generating timestamp
	// But for now generate the local current time.
	t := time.Now()
	jwsProtectedHeader.SigningTime = &t

	// TODO Need to eventually support "best by use" header -> io.cncf.notary.expiry
	/*
		jwsProtectedHeader.Expiry = time.Now()
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

func certAlgToJWTAlg(mech int) string {
	switch mech {
	case c.EcDsa:
		return "ES256"
	case c.RsaPkcsPss:
		return "PS256"
	default:
		return ""
	}
}
