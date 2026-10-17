package agentcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Identity struct {
	DeviceID         string `json:"device_id"`
	TenantID         string `json:"tenant_id"`
	PrivateKeyPEM    string `json:"private_key_pem"`
	CertificatePEM   string `json:"certificate_pem"`
	CACertificatePEM string `json:"ca_certificate_pem"`
	ServerSigningKey string `json:"server_signing_key"`
}

func LoadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if id.DeviceID == "" || id.TenantID == "" || id.PrivateKeyPEM == "" || id.CertificatePEM == "" || id.ServerSigningKey == "" {
		return nil, errors.New("identity is incomplete")
	}
	return &id, nil
}

func SaveIdentity(path string, id *Identity) error {
	if id == nil {
		return errors.New("identity is nil")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := restrictIdentityPermissions(dir, true); err != nil {
		return fmt.Errorf("secure identity directory: %w", err)
	}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".identity-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := restrictIdentityPermissions(tmpPath, false); err != nil {
		return fmt.Errorf("secure temporary identity: %w", err)
	}
	if err := os.WriteFile(tmpPath, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := restrictIdentityPermissions(path, false); err != nil {
		return fmt.Errorf("secure identity: %w", err)
	}
	return nil
}

func GenerateDeviceKey() (publicPEM, privatePEM string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})), nil
}
