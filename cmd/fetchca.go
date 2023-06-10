package cmd

import (
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

type FetchCACmd struct {
	URL        string
	outputFile string
	verify     bool
	csv        bool
	BaseCmd
}

func NewFetchCACmd() *FetchCACmd {
	fca := &FetchCACmd{}
	fca.BaseCmd.Init("fetchca")
	fca.f.StringVar(&fca.outputFile, "out", "-", "output file.  '-' goes to stdout")
	fca.f.StringVar(&fca.URL, "url", "https://curl.se/ca/cacert.pem", "url to remote CA bundle "+
		"(required) - please do not abuse curl.se")
	fca.f.BoolVar(&fca.verify, "verify", true, "verify downloaded certificate bundle")
	fca.f.BoolVar(&fca.csv, "csv", false, "output metadata as csv")
	return fca
}

func (fca *FetchCACmd) Run(args []string) int {
	err := fca.f.Parse(args)
	if err != nil || len(fca.URL) == 0 || len(fca.outputFile) == 0 {
		return RunResultHelp
	}

	err = fca.run()
	if err != nil {
		log.Printf("error fetching: %s", err)
		return 1
	}

	return 0
}

func (fca *FetchCACmd) run() error {
	var w io.Writer
	switch fca.outputFile {
	case "-":
		w = os.Stdout
	default:
		f, err := os.OpenFile(fca.outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("unable to open file %s for writing: %w", fca.outputFile, err)
		}
		defer f.Close()
		w = f
	}
	req, err := http.NewRequest(http.MethodGet, fca.URL, nil)
	if err != nil {
		return fmt.Errorf("error creating http request: %w", err)
	}
	req.Header.Set("User-Agent", "whichca/1.0")
	c := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          0,
			IdleConnTimeout:       0,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("error fetching url: %s", err)
	}
	defer func() {
		if resp.Body != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	if resp.StatusCode != 200 {
		return fmt.Errorf("non-200 status code received: %d %s", resp.StatusCode, resp.Status)
	}
	var r io.Reader = resp.Body
	var certs []*x509.Certificate
	if fca.verify || fca.csv {
		tf, err := ioutil.TempFile(os.TempDir(), "fetchca-")
		if err != nil {
			return fmt.Errorf("could not create temporary file: %w", err)
		}

		defer func() {
			os.Remove(tf.Name())
		}()
		_, err = io.Copy(tf, resp.Body)
		if err != nil {
			return fmt.Errorf("error writing to temporary file: %w", err)
		}
		// close file to flush and allow loadCABundle to read it properly
		tf.Close()

		certs, _, err = loadCABundle(tf.Name())
		if err != nil {
			return fmt.Errorf("failed validation of downloaded bundle: %w", err)
		}
		log.Printf("verified %d certificates in bundle downloaded from %s", len(certs), fca.URL)

		// reopen the temp file for reading for the copy below.
		if !fca.csv {
			f, err := os.Open(tf.Name())
			if err != nil {
				return fmt.Errorf("unable to reopen temp file: %w", err)
			}
			defer f.Close()
			r = f
		}
	}
	if fca.csv {
		cWriter := csv.NewWriter(w)
		writeCertCSVHeader(cWriter)
		for _, cert := range certs {
			writeCertCSV(cWriter, cert)
		}
		cWriter.Flush()

	} else {
		_, err = io.Copy(w, r)
	}
	if err != nil {
		return fmt.Errorf("error copying payload: %w", err)
	}
	return nil
}

func (fca *FetchCACmd) Synopsis() string {
	return "utility to fetch a PEM ca bundle from the internet"
}
