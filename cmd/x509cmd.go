package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	formPEM = "PEM"
	formDER = "DER"
)

type X509Cmd struct {
	inFile  string
	outFile string
	inForm  string
	outForm string
	text    bool
	noOut   bool
	*BaseCmd
}

func NewX509Cmd() *X509Cmd {
	x := &X509Cmd{
		BaseCmd: &BaseCmd{},
	}
	x.BaseCmd.Init("x509")
	x.f.StringVar(&x.inFile, "in", "-", "input file.  '-' reads stdin")
	x.f.StringVar(&x.outFile, "out", "-", "output file.  '-' goes to stdout")
	x.f.StringVar(&x.inForm, "inform", "", "input format, PEM or DER.  detected from the input when unset")
	x.f.StringVar(&x.outForm, "outform", formPEM, "output format, PEM or DER")
	x.f.BoolVar(&x.text, "text", false, "print the certificate in text form")
	x.f.BoolVar(&x.noOut, "noout", false, "don't output the encoded certificate")
	return x
}

func (x *X509Cmd) Synopsis() string {
	return "Convert and display certificates, in the manner of openssl x509"
}

func (x *X509Cmd) Run(args []string) int {
	// bare invocation: read whatever shows up on stdin and describe it.  the
	// encoded copy is rarely what you want when you didn't ask for anything.
	if x.f.NFlag() == 0 {
		x.text = true
		x.noOut = true
	}
	if err := x.run(); err != nil {
		log.Println(err)
		return 1
	}
	return 0
}

func (x *X509Cmd) run() error {
	outForm, err := normalizeForm(x.outForm, "outform")
	if err != nil {
		return err
	}
	inForm, err := normalizeForm(x.inForm, "inform")
	if err != nil {
		return err
	}

	var in io.Reader = os.Stdin
	inName := "stdin"
	if x.inFile != "-" {
		f, err := os.Open(x.inFile)
		if err != nil {
			return fmt.Errorf("error opening %s: %w", x.inFile, err)
		}
		defer f.Close()
		in = f
		inName = x.inFile
	}
	raw, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", inName, err)
	}

	certs, err := parseCerts(raw, inForm)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("no certificates found in %s", inName)
	}

	var out io.Writer = os.Stdout
	if x.outFile != "-" {
		f, err := os.OpenFile(x.outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("error opening %s: %w", x.outFile, err)
		}
		defer f.Sync()
		defer f.Close()
		out = f
	}

	for _, cert := range certs {
		if x.text {
			if err = writeCertPretty(out, cert); err != nil {
				return err
			}
		}
		if x.noOut {
			continue
		}
		switch outForm {
		case formDER:
			if _, err = out.Write(cert.Raw); err != nil {
				return err
			}
		default:
			err = pem.Encode(out, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// normalizeForm upper cases a format argument and rejects anything we can't
// handle.  an empty string is left alone, meaning "detect it".
func normalizeForm(form, flag string) (string, error) {
	switch f := strings.ToUpper(form); f {
	case "", formPEM, formDER:
		return f, nil
	default:
		return "", fmt.Errorf("unsupported -%s %q: expected %s or %s", flag, form, formPEM, formDER)
	}
}

// parseCerts decodes every certificate in raw.  an empty form means work out
// whether this is PEM or DER, which only takes looking for a PEM block.
func parseCerts(raw []byte, form string) ([]*x509.Certificate, error) {
	if form == "" {
		form = formDER
		if block, _ := pem.Decode(raw); block != nil {
			form = formPEM
		}
	}

	ders := raw
	if form == formPEM {
		ders = decodePemsByType(raw, "CERTIFICATE")
		if len(ders) == 0 {
			return nil, fmt.Errorf("no CERTIFICATE blocks found in PEM input")
		}
	}

	certs, err := x509.ParseCertificates(ders)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s certificate data: %w", form, err)
	}
	return certs, nil
}
