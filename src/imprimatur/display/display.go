package display

import (
	"imprimatur/imprimatur"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"
)

func Display(path string) {
	file, err := imprimatur.LoadFile(path)
	if err != nil {
		panic(err)
	}

	tmpfile, err := ioutil.TempFile("", "imprimatur")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(tmpfile.Name())

	var contents []byte
	switch file.GetContentType() {
	case "application/pdf":
		contents, err = overlayPdf(file)
		if err != nil {
			log.Fatal(err.Error())
		}
	default:
		contents = file.Render(false)
	}

	if _, err := tmpfile.Write(contents); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("xdg-open", tmpfile.Name())
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}

	// Allow the xdg-open command some time to open/read the file before removing the tmp file again
	time.Sleep(1 * time.Second)
}
