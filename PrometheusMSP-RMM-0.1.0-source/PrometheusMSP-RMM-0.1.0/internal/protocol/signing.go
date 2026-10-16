package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
)

var ErrInvalidSignature = errors.New("invalid job signature")

// SigningBytes returns deterministic JSON for the envelope with Signature blank.
// A struct is used deliberately so field ordering cannot depend on map iteration.
func (j JobEnvelope) SigningBytes() ([]byte, error) {
	j.Signature = ""
	return json.Marshal(j)
}

func (j *JobEnvelope) Sign(privateKey ed25519.PrivateKey) error {
	payload, err := j.SigningBytes()
	if err != nil {
		return err
	}
	j.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func (j JobEnvelope) Verify(publicKey ed25519.PublicKey) error {
	payload, err := j.SigningBytes()
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}
