package imprimatur

import (
	"errors"
	"fmt"
	"os"
	"strings"

	_ "crypto/sha256"
)

type signer struct {
	gpgSocketPath string
	file          *file
}

func Sign(keygrip, sourcePath string) {

	signer, err := NewSigner(sourcePath)
	if err != nil {
		fmt.Printf("%s", err.Error())
		os.Exit(1)
	}

	key, err := signer.GetKey(keygrip)
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	signer.file.addSignerMetadata(key)
	sig, err := signer.GpgSign(key)
	if err != nil {
		fmt.Printf("Could not sign %s: %s", sourcePath, err.Error())
		os.Exit(1)
	}

	signer.file.addSignature(sig)
	dstPath, err := signer.file.write()
	if err != nil {
		fmt.Printf("Could not write file: " + err.Error())
		os.Exit(1)
	}

	fmt.Println(fmt.Sprintf("Signed file %s into %s using Key with finger print: %s",
		sourcePath, dstPath, signer.file.key.FingerPrintSHA256()))

	// Success!
}

func NewSigner(path string) (*signer, error) {
	signer := &signer{}

	gpgSocketPath := os.Getenv("GPG_AGENT_INFO")
	if gpgSocketPath == "" {
		return nil, errors.New("no GPG_AGENT_INFO environment variable found")
	}

	signer.gpgSocketPath = gpgSocketPath[0:strings.Index(gpgSocketPath, ":")]
	if err := signer.loadFile(path); err != nil {
		return nil, err
	}

	return signer, nil
}
