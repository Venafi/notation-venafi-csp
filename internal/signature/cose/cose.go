package cose

import (
	"crypto/rand"
	"crypto/x509"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/venafi/notation-venafi-csp/internal/signature/jws"
	"github.com/venafi/notation-venafi-csp/internal/version"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/veraison/go-cose"
)

// MediaTypeEnvelope is the COSE signature envelope blob mediaType.
const (
	MediaTypeEnvelope  = "application/cose"
	MediaTypePayloadV1 = "application/vnd.cncf.notary.payload.v1+json"
	SigningSchemeX509  = "notary.x509"
	defaultDigestAlg   = "sha256"
)

var (
	// encMode is the encoding mode used in Sign
	encMode cbor.EncMode

	// decMode is the decoding mode used in Content
	decMode cbor.DecMode
)

// Protected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerLabelExpiry               = "io.cncf.notary.expiry"
	headerLabelSigningScheme        = "io.cncf.notary.signingScheme"
	headerLabelSigningTime          = "io.cncf.notary.signingTime"
	headerLabelAuthenticSigningTime = "io.cncf.notary.authenticSigningTime"
)

// Unprotected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerLabelTimeStampSignature = "io.cncf.notary.timestampSignature"
	headerLabelSigningAgent       = "io.cncf.notary.signingAgent"
)

type venafiSigner struct {
	tppOpts endpoint.Connector
	env     endpoint.Environment
	alg     cose.Algorithm
	mech    int
}

func (signer *venafiSigner) Algorithm() cose.Algorithm {
	return signer.alg
}

func (signer *venafiSigner) Sign(rand io.Reader, payload []byte) ([]byte, error) {
	sig, err := signer.tppOpts.Sign(&endpoint.SignOption{
		KeyID:     signer.env.KeyID,
		Mechanism: signer.mech,
		DigestAlg: defaultDigestAlg,
		Payload:   payload,
		B64Flag:   false,
		RawFlag:   false,
	})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func mechToCOSEAlgorithm(mech int) cose.Algorithm {
	switch mech {
	case c.RsaPkcsPss:
		return cose.AlgorithmPS256
	case c.EcDsa:
		return cose.AlgorithmES256
	default:
		return cose.AlgorithmPS256
	}
}

func SignCOSEEnvelope(coseOpts COSEOptions) ([]byte, error) {

	var err error

	// Initialize CBOR options
	encOpts := cbor.EncOptions{
		Time:    cbor.TimeUnix,
		TimeTag: cbor.EncTagRequired,
	}
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}

	decOpts := cbor.DecOptions{
		TimeTag: cbor.DecTagRequired,
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(err)
	}

	digestAlg := mechToCOSEAlgorithm(coseOpts.Mech)
	var signer venafiSigner = venafiSigner{tppOpts: coseOpts.Connector, env: coseOpts.Env, mech: coseOpts.Mech, alg: digestAlg}

	// prepare COSE_Sign1 message
	msg := cose.NewSign1Message()

	// generate protected headers of COSE envelope
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())
	if err := generateProtectedHeaders(msg.Headers.Protected, coseOpts.X5u); err != nil {
		return nil, err
	}

	// generate payload of COSE envelope
	msg.Headers.Protected[cose.HeaderLabelContentType] = MediaTypePayloadV1
	msg.Payload = coseOpts.Req.Payload

	// core sign process, generate signature of COSE envelope
	if err := msg.Sign(rand.Reader, nil, &signer); err != nil {
		return nil, err
	}

	certs, err := c.ParseCertificates(coseOpts.Env.CertificateChainData)
	if err != nil {
		return nil, err
	}
	// generate unprotected headers of COSE envelope
	generateUnprotectedHeaders(certs, msg.Headers.Unprotected)

	// TODO: needs to add headerKeyTimeStampSignature.

	// encode Sign1Message into COSE_Sign1_Tagged object
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	//e.base = msg

	return encoded, nil

}

// encodeTime generates a Tag1 Datetime CBOR object and casts it to
// cbor.RawMessage
func encodeTime(t time.Time) (cbor.RawMessage, error) {
	timeCBOR, err := encMode.Marshal(t)
	if err != nil {
		return nil, err
	}

	return cbor.RawMessage(timeCBOR), nil
}

// generateProtectedHeaders creates Protected Headers of the COSE envelope
// during Sign process.
func generateProtectedHeaders(protected cose.ProtectedHeader, x5u string) error {
	// signingScheme
	crit := []any{headerLabelSigningScheme}
	protected[headerLabelSigningScheme] = string(SigningSchemeX509)

	// signingTime/authenticSigningTime
	signingTimeLabel := headerLabelSigningTime

	rawTimeCBOR, err := encodeTime(time.Now())
	if err != nil {
		return err
	}
	protected[signingTimeLabel] = rawTimeCBOR
	if signingTimeLabel == headerLabelAuthenticSigningTime {
		crit = append(crit, headerLabelAuthenticSigningTime)
	}

	extendedAttributes := jws.GenerateExtendedAttributes(x5u)

	// extended attributes
	for _, elm := range extendedAttributes {
		if _, ok := protected[elm.Key]; ok {
			return err
		}
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
		protected[elm.Key] = elm.Value
	}

	// critical headers
	protected[cose.HeaderLabelCritical] = crit

	return nil
}

// generateUnprotectedHeaders creates Unprotected Headers of the COSE envelope
// during Sign process.
func generateUnprotectedHeaders(certs []*x509.Certificate, unprotected cose.UnprotectedHeader) {
	// signing agent
	unprotected[headerLabelSigningAgent] = version.SigningAgent

	// certChain
	certChain := make([]any, len(certs))
	for i, c := range certs {
		certChain[i] = c.Raw
	}
	unprotected[cose.HeaderLabelX5Chain] = certChain
}
