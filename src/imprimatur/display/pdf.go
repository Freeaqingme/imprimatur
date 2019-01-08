package display

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"github.com/jung-kurt/gofpdf"
	"imprimatur/imprimatur"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"
)

func overlayPdf(f *imprimatur.File) ([]byte, error) {
	file, err := ioutil.TempFile("", "imprimatur")
	if err != nil {
		return nil, fmt.Errorf("cannot write temp pdf file: %s", err.Error())
	}
	defer os.Remove(file.Name())
	file.Write(f.Render(false))

	signaturePage, err := createSignaturePage(f)
	if err != nil {
		return nil, err
	}
	defer os.Remove(signaturePage.Name())

	resultingFile, err := ioutil.TempFile("", "imprimatur")
	if err != nil {
		return nil, err
	}
	defer os.Remove(resultingFile.Name())

	// see: https://superuser.com/questions/54041/how-to-merge-pdfs-using-imagemagick-resolution-problem
	cmd := exec.Command("gs", "-dBATCH", "-dNOPAUSE", "-q", "-sDEVICE=pdfwrite",
		fmt.Sprintf("-sOutputFile=%s", resultingFile.Name()),
		file.Name(), signaturePage.Name())
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cannot merge pdf pages: %s", err.Error())
	}

	return ioutil.ReadFile(resultingFile.Name())
}

func createSignaturePage(f *imprimatur.File) (*os.File, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")

	content, err := createSignaturePageContents(f)
	if err != nil {
		return nil, err
	}
	pdf.AddPage()
	pdf.SetFont("Arial", "", 9)
	pdf.MultiCell(999, 10, content, "", "", false)

	tmpFile, err := ioutil.TempFile("", "imprimatur")
	if err != nil {
		return nil, err
	}

	if err := pdf.OutputFileAndClose(tmpFile.Name()); err != nil {
		os.Remove(tmpFile.Name())
		return nil, err
	}

	return tmpFile, nil
}

func createSignaturePageContents(f *imprimatur.File) (string, error) {
	out := []string {
		"This document was digitally signed with an RSA digital signature using Imprimatur.",
		"To verify these signatures, run `imprimatur verify filename.pdf`",
		"This document was signed with the following signature(s):\n",
	}

	for _, sig := range f.ExistingSigs {
		err := rsa.VerifyPKCS1v15(sig.Signature.Key.PublicKey, crypto.SHA512, sig.ContentHash, sig.Signature.Sig)
		if err != nil {
			return "", fmt.Errorf("cocument contains an invalid signature")
		}

		out = append(out, strings.Replace(fmt.Sprintf("%s (%s@%s):\n\tDate:\t\t\t%s\n\tKey Fingerprint:\t%s\n",
			sig.FullName,
			sig.Username,
			sig.Host,
			sig.Timestamp.Format(time.RFC3339),
			sig.Signature.Key.FingerPrintSHA256(),
		), "\t", "        ", -1))
	}

	return strings.Join(out, "\n"), nil

}
