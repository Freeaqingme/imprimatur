package imprimatur

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"
	"net/http"
)

const header = "\000\000\000\000imprimatur\000v1.0\000\000\000\000\n"

var re = regexp.MustCompile("TIME=(?P<time>\\d+);FULLNAME=(?P<fullname>[^;]*);USERNAME=(?P<Username>[^;]*);HOSTNAME=(?P<hostname>[^;]*);PUBKEY=(?P<pubkey>[^;\n]*)(?:;(?P<fowardCompat>.*[^\n]))?\n(?P<Sig>.*[^\n])\n")

type File struct {
	origPath string
	contents []byte

	time     time.Time
	key      *key
	fullName string
	username string
	hostname string
	newSig   *signature

	ExistingSigs []existingSig
}

type existingSig struct {
	Signature   *signature
	ContentHash []byte

	Timestamp time.Time
	FullName  string
	Username  string
	Host      string

	ForwardCompat []byte
}

func (s *signer) loadFile(path string) (err error) {
	s.file, err = LoadFile(path)
	return
}

func LoadFile(path string) (*File, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	f := &File{
		contents: contents,
		origPath: path,
	}

	f.parse()

	return f, nil
}

func (f *File) addSignerMetadata(key *key) {
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

	f.hostname, _ = os.Hostname()
}

func (f *File) addSignature(sig *signature) {
	if f.newSig != nil {
		panic("can only add a new signature once per run")
	}

	f.newSig = sig
}

func (f *File) parse() []signature {
	headerPos := bytes.LastIndex(f.contents, []byte(header))
	if -1 == headerPos {
		return []signature{}
	}

	hasher := sha512.New()
	hasher.Write(f.contents[0 : headerPos+len(header)])

	signaturesContent := f.contents[headerPos+len(header):]

	matches := re.FindAllSubmatch(signaturesContent, -1)
	f.ExistingSigs = make([]existingSig, len(matches))
	for i, match := range matches {
		lines := bytes.Split(match[0], []byte("\n"))
		hasher.Write(append(lines[0], []byte("\n")...))

		timestamp, _ := strconv.ParseInt(string(match[1]), 10, 64)

		rawKey, err := base64.StdEncoding.DecodeString(string(match[5]))
		if err != nil {
			panic("Invalid Key: " + err.Error())
		}
		pubKey, err := x509.ParsePKCS1PublicKey([]byte(rawKey))
		if err != nil {
			panic("Could not parse public Key: " + err.Error())
		}

		sig, err := base64.StdEncoding.DecodeString(string(match[7]))
		if err != nil {
			panic("Could not decode signature: " + err.Error())
		}

		existingSig := existingSig{
			Signature: &signature{
				Sig: sig,
				Key: &key{
					PublicKey: pubKey,
				},
			},
			ContentHash: hasher.Sum(nil),

			Timestamp:     time.Unix(0, timestamp),
			FullName:      string(match[2]),
			Username:      string(match[3]),
			Host:          string(match[4]),
			ForwardCompat: match[6],
		}

		hasher.Write(append(lines[1], []byte("\n")...))
		f.ExistingSigs[i] = existingSig
	}

	return []signature{} // todo?
}

func (f *File) Render(errorOnMissingSig bool) []byte {
	newContents := f.contents
	if -1 == bytes.LastIndex(f.contents, []byte(header)) {
		newContents = append(newContents, []byte(header)...)
	}

	if f.key == nil {
		return newContents
	}

	san := func(input string) string { return strings.Replace(input, ";", "", -1) }
	key := base64.StdEncoding.EncodeToString(f.key.Marshal())
	metadata := fmt.Sprintf("TIME=%d;FULLNAME=%s;USERNAME=%s;HOSTNAME=%s;PUBKEY=%s\n",
		f.time.UnixNano(), san(f.fullName), san(f.username), san(f.hostname), key)
	newContents = append(newContents, []byte(metadata)...)

	if f.newSig == nil {
		if errorOnMissingSig {
			panic("Asked to Render a File without a set signature")
		}
		return newContents
	}

	if f.newSig.Key != f.key {
		panic("Signature Key does not match with public Key")
	}

	sig := base64.StdEncoding.EncodeToString(f.newSig.Sig) + "\n"
	newContents = append(newContents, []byte(sig)...)

	return newContents
}

func (f *File) write() (string, error) {
	path, err := f.getDstPath()
	if err == nil {
		err = f.writeToPath(path)
	}

	return path, err
}

func (f *File) writeToPath(path string) error {
	err := ioutil.WriteFile(path, f.Render(true), 0644)

	return err
}

func (f *File) getDstPath() (string, error) {
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

func (f *File) GetContentType() string {

	// Only the first 512 bytes are used to sniff the content type.
	buffer := f.contents[0:512]

	// Use the net/http package's handy DectectContentType function. Always returns a valid
	// content-type by returning "application/octet-stream" if no others seemed to match.
	return string(http.DetectContentType(buffer))
}