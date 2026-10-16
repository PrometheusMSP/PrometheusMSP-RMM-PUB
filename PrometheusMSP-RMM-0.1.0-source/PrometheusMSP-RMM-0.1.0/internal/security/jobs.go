package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

type JobSigner struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func GenerateJobSigner() (*JobSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &JobSigner{private: priv, public: pub}, nil
}

func NewJobSigner(private ed25519.PrivateKey) (*JobSigner, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	privateCopy := append(ed25519.PrivateKey(nil), private...)
	return &JobSigner{private: privateCopy, public: append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)}, nil
}

func (s *JobSigner) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(s.public)
}

func (s *JobSigner) Sign(envelope *protocol.JobEnvelope) error {
	return envelope.Sign(s.private)
}

func VerifyJob(public ed25519.PublicKey, envelope protocol.JobEnvelope) bool {
	return envelope.Verify(public) == nil
}
