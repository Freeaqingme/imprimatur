package verifier

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"imprimatur/imprimatur"
	"time"
)

func Verify(path string) {
	file, err := imprimatur.LoadFile(path)
	if err != nil {
		panic(err)
	}

	for i, sig := range file.ExistingSigs {
		validMsg := "INVALID SIGNATURE!"
		err := rsa.VerifyPKCS1v15(sig.Signature.Key.PublicKey, crypto.SHA512, sig.ContentHash, sig.Signature.Sig)
		if err == nil {
			validMsg = "Signature Valid"
		}

		fmt.Println(fmt.Sprintf("%s (%s@%s): %s\n\tDate:\t\t\t%s\n\tKey Fingerprint:\t%s",
			sig.FullName,
			sig.Username,
			sig.Host,
			validMsg,
			sig.Timestamp.Format(time.RFC3339),
			sig.Signature.Key.FingerPrintSHA256(),
		))

		if len(sig.ForwardCompat) > 0 {
			fmt.Println("\tUnrecognized metadata:" + string(sig.ForwardCompat))
		}

		if i != len(file.ExistingSigs)-1 {
			fmt.Print("\n")
		}
	}

}
