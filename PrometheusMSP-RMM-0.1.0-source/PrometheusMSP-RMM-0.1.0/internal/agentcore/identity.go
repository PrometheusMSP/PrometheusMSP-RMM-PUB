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
	DeviceID        string `json:"device_id"`
	TenantID        string `json:"tenant_id"`
	PrivateKeyPEM   string `json:"private_key_pem"`
	CertificatePEM  string `json:"certificate_pem"`
	CACertificatePEM string `json:"ca_certificate_pem"`
	ServerSigningKey string `json:"server_signing_key"`
}

func LoadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil { return nil, fmt.Errorf("decode identity: %w", err) }
	if id.DeviceID == "" || id.TenantID == "" || id.PrivateKeyPEM == "" || id.CertificatePEM == "" || id.ServerSigningKey == "" {
		return nil, errors.New("identity is incomplete")
	}
	return &id, nil
}

func SaveIdentity(path string, id *Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { return err }
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil { return err }
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil { return err }
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil { return err }
	if err := os.Chmod(tmp, 0600); err != nil { _ = os.Remove(tmp); return err }
	if err := os.Rename(tmp, path); err != nil { _ = os.Remove(tmp); return err }
	return os.Chmod(path, 0600)
}

func GenerateDeviceKey() (publicPEM, privatePEM string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { return "", "", err }
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil { return "", "", err }
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil { return "", "", err }
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})), nil
}
