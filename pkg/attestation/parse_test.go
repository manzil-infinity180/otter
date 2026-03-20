package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestExtractCertificateMetadataReturnsSignerAndIssuer(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	uri, err := url.Parse("https://example.com/workflow")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "signer@example.com",
		},
		Issuer: pkix.Name{
			CommonName: "Otter Test Issuer",
		},
		NotBefore:      time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
		NotAfter:       time.Date(2026, 3, 14, 18, 0, 0, 0, time.UTC),
		EmailAddresses: []string{"signer@example.com"},
		URIs:           []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	signer, issuer, ts := extractCertificateMetadata(map[string]string{
		"certificate": string(certificatePEM),
	})

	if signer == "" {
		t.Fatal("expected signer")
	}
	if issuer == "" {
		t.Fatal("expected issuer")
	}
	if ts == nil {
		t.Fatal("expected timestamp")
	}
}
