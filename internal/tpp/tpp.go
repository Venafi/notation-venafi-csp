package tpp

import (
	"context"
	"crypto/x509"
)

// Key represents a remote key in the Azure Key Vault.
type Key struct {
	vaultBaseURL string
	name         string
	version      string
}

// Sign signs the message digest with the algorithm provided.
func (k *Key) Sign(ctx context.Context, algorithm string, digest []byte) ([]byte, error) {
	return nil, nil
}

// Certificate returns the X.509 certificate associated with the key.
func (k *Key) Certificate(ctx context.Context) (*x509.Certificate, error) {
	/*res, err := k.Client.GetCertificate(
		ctx,
		k.vaultBaseURL,
		k.name,
		k.version,
	)
	if err != nil {
		return nil, err
	}
	if res.Cer == nil {
		return nil, errors.New("azure: invalid server response")
	}
	return x509.ParseCertificate(*res.Cer)*/
	return nil, nil
}
