package security

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

type CertificateAuthority struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  string
}

func NewCertificateAuthority(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !cert.IsCA {
		return nil, errors.New("CA certificate is invalid or is not a CA")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid CA key PEM")
	}
	key, err := parseSigner(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(publicDER, cert.RawSubjectPublicKeyInfo) {
		return nil, errors.New("CA private key does not match certificate")
	}
	return &CertificateAuthority{cert: cert, key: key, pem: string(certPEM)}, nil
}

func (ca *CertificateAuthority) CertificatePEM() string { return ca.pem }

func (ca *CertificateAuthority) IssueDeviceCertificate(publicKeyPEM, tenantID, deviceID string, now time.Time) (string, error) {
	publicKey, err := ParseDevicePublicKey(publicKeyPEM)
	if err != nil {
		return "", err
	}
	return ca.issueDeviceCertificate(publicKey, tenantID, deviceID, now)
}

func ParseDevicePublicKey(publicKeyPEM string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return publicKey, nil
}

func (ca *CertificateAuthority) issueDeviceCertificate(publicKey crypto.PublicKey, tenantID, deviceID string, now time.Time) (string, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", err
	}
	identity, _ := url.Parse(fmt.Sprintf("spiffe://prometheus-rmm/tenant/%s/device/%s", url.PathEscape(tenantID), url.PathEscape(deviceID)))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: deviceID, OrganizationalUnit: []string{tenantID}},
		URIs: [](*url.URL){identity},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, publicKey, ca.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func DeviceIdentity(cert *x509.Certificate) (tenantID, deviceID string, err error) {
	for _, uri := range cert.URIs {
		if uri.Scheme != "spiffe" || uri.Host != "prometheus-rmm" {
			continue
		}
		parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
		if len(parts) == 4 && parts[0] == "tenant" && parts[2] == "device" {
			return parts[1], parts[3], nil
		}
	}
	return "", "", errors.New("device certificate has no valid identity URI")
}

func parseSigner(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported CA private key")
}
