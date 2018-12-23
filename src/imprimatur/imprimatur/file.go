package imprimatur

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"
	"time"
)

const header = "\000\000\000\000imprimatur\000v1.0\000\000\000\000\n"

type file struct {
	origPath string
	contents []byte

	time time.Time
	key *key
	fullName string
	username string
	hostname string
	newSig *signature
}

func (s *signer) loadFile(path string) error {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	f := &file{
		contents: contents,
		origPath: path,
	}

	f.parse()
	s.file = f

	return nil
}

func (f *file) addSignerMetadata(key *key) {
	f.time = time.Now()
	f.key = key

	if user, err := user.Current(); err == nil {
		f.username = user.Username
		if user.Name != "" {
			f.fullName = user.Name
		} else {
			f.fullName = f.username
		}
	}

	f.hostname,_ = os.Hostname()
}

func (f *file) addSignature(sig *signature){
	if f.newSig != nil {
		panic("can only add a new signature once per run")
	}

	f.newSig = sig
}

func (f *file) parse() []signature {
	headerPos := bytes.LastIndex(f.contents, []byte(header))
	if -1 == headerPos {
		return []signature{}
	}

	return []signature{} // todo
}

func (f *file) render(errorOnMissingSig bool) []byte {
	newContents := f.contents
	if -1 == bytes.LastIndex(f.contents, []byte(header)) {
		newContents = append(newContents, []byte(header)...)
	}

	if f.key == nil {
		return newContents
	}

	san := func(input string) string { return strings.Replace(input, ";", "", -1); }
	key := base64.StdEncoding.EncodeToString(f.key.Marshal())
	metadata := fmt.Sprintf("TIME=%d;FULLNAME=%s;USERNAME=%s;HOSTNAME=%s;PUBKEY=%s\n",
		f.time.UnixNano(), san(f.fullName), san(f.username), san(f.hostname), key)
	newContents = append(newContents, []byte(metadata)...)

	if f.newSig == nil {
		if errorOnMissingSig {
			panic("Asked to render a file without a set signature")
		}
		return newContents
	}

	if f.newSig.key != f.key {
		panic("Signature key does not match with public key")
	}

	sig := base64.StdEncoding.EncodeToString(f.newSig.sig) + "\n"
	newContents = append(newContents, []byte(sig)...)

	return newContents
}

func (f *file) write() (string, error) {
	path, err := f.getDstPath()
	if err == nil {
		err = f.writeToPath(path)
	}

	return path, err
}

func (f *file) writeToPath(path string) error {
	err := ioutil.WriteFile(path, f.render(true), 0644)

	return err
}

func (f *file) getDstPath() (string, error) {
	extPos := strings.LastIndex(f.origPath, ".")
	if strings.LastIndex(f.origPath, "/") > extPos {
		extPos = -1 // ./foobar: the last dot is not an extension separator
	}

	path := f.origPath
	ext := ""
	if extPos != -1 {
		path = f.origPath[0:extPos]
		ext = f.origPath[extPos+1:]
	}

	attemptPath := path + ".imprimatur"
	if ext != "" {
		attemptPath = attemptPath + "." + ext
	}

	for i := 1; i < 1000; i++ {
		if _, err := os.Stat(attemptPath); os.IsNotExist(err) {
			return attemptPath, nil
		}

		if ext != "" {
			attemptPath = fmt.Sprintf("%s.imprimatur-%d.%s", path, i, ext)
		} else {
			attemptPath = fmt.Sprintf("%s.imprimatur-%d", path, i)
		}
	}

	return "", errors.New("no path could be determined")
}
