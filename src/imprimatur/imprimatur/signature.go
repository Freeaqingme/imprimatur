package imprimatur

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"github.com/Freeaqingme/go-gpg-agent-client/agent"
	"strings"
)

type signature struct {
	sig []byte
	key *key
}

type key struct {
	*rsa.PublicKey
	*agent.Key
}

func NewKey(input *agent.Key) (*key, error) {
	rsaPubKey, ok := input.Public().(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("returned key by pgp was not an RSA Public Key")
	}

	return &key{rsaPubKey, input }, nil
}

func newSignature(sig []byte, key *key) *signature {
	return &signature{
		sig: sig,
		key: key,
	}
}

func (k *key) fingerPrintSHA256() string {
	hash := sha256.Sum256(x509.MarshalPKCS1PublicKey(k.PublicKey))
	hexarray := make([]string, len(hash))
	for i, c := range hash {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}

	return "SHA256:" + strings.Join(hexarray, ":")
}

func (k *key) Marshal() []byte {
	return x509.MarshalPKCS1PublicKey(k.PublicKey)
}
