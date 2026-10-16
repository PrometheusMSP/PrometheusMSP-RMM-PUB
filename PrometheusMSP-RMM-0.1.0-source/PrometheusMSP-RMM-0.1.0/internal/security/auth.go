package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

type Operator struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

type BearerAuthenticator struct {
	tokens map[[32]byte]Operator
}

func NewBearerAuthenticator(tokens map[string]Operator) *BearerAuthenticator {
	hashed := make(map[[32]byte]Operator, len(tokens))
	for token, operator := range tokens {
		hashed[sha256.Sum256([]byte(token))] = operator
	}
	return &BearerAuthenticator{tokens: hashed}
}

func (a *BearerAuthenticator) Authenticate(r *http.Request) (Operator, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return Operator{}, errors.New("bearer token required")
	}
	presented := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))))
	for digest, operator := range a.tokens {
		if subtle.ConstantTimeCompare(presented[:], digest[:]) == 1 {
			return operator, nil
		}
	}
	return Operator{}, errors.New("invalid bearer token")
}
