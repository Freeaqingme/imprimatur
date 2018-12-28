package imprimatur

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"github.com/Freeaqingme/go-gpg-agent-client/agent"
	"strings"

	_ "crypto/sha256"
)

func (s *signer) GpgSign(key *key) (*signature, error) {
	hasher := sha512.New()
	hasher.Write(s.file.Render(false))

	sig, err := key.Sign(rand.Reader, hasher.Sum(nil), crypto.SHA512)
	if err != nil {
		return nil, err
	}
	out, err := newSignature(sig, key), nil
	return out, err
}

func (s *signer) GetKey(keygrip string) (*key, error) {
	conn, err := agent.Dial(s.gpgSocketPath, []string{})
	if err != nil {
		return nil, err
	}

	keys, err := conn.Keys()
	if err != nil {
		return nil, err
	}

	for i := range keys {
		if strings.EqualFold(keys[i].Keygrip, keygrip) {
			return NewKey(&keys[i])
		}
	}

	return nil, errors.New("No Key by keygrip " + keygrip + " could be found")
}
