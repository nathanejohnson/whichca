package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

type CheckIntermediateCmd struct {
	hostports stringparams
	files     globparams
	cafile    string
	ca        *x509.CertPool
	iFile     string
	quiet     bool
	*BaseCmd
}

func NewCheckIntermediateCmd() *CheckIntermediateCmd {
	ci := &CheckIntermediateCmd{
		BaseCmd: &BaseCmd{},
	}
	ci.BaseCmd.Init("check")
	ci.f.Var(&ci.hostports, "hp", "inspect site at `host:port` for correctness")
	ci.f.Var(&ci.files, "p", "search `pathspec` for certificate files")
	ci.f.StringVar(&ci.cafile, "ca", "", "path to a ca bundle.  defaults to the system bundle")
	ci.f.StringVar(&ci.iFile, "out", "-", "path to file to save any intermediates needed. use - for stdout")
	ci.f.BoolVar(&ci.quiet, "q", false, "whether to suppress writing to path specified in -out")

	return ci
}



func (ci *CheckIntermediateCmd) Run(args []string) int {
	err := ci.f.Parse(args)
	if err != nil || (len(ci.files) == 0 && len(ci.hostports) == 0) {
		return RunResultHelp
	}

	if err = ci.run(); err != nil {
		log.Println(err)
		return 1
	}
	return 0
}
func (ci *CheckIntermediateCmd) run() error {
	if ci.cafile != "" {
		var err error
		ci.ca, err = loadCABundle(ci.cafile)
		if err != nil {
			return err
		}
	}
	save := true
	var w io.Writer
	if ci.quiet || ci.iFile == "" {
		save = false
	} else {
		switch ci.iFile {
		case "-":
			w = os.Stdout
			defer os.Stdout.Sync()
		default:
			f, err := os.OpenFile(ci.iFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer f.Sync()
			defer f.Close()
			w = f
		}
	}
	process := func(ok bool, leaf *x509.Certificate, missing []*x509.Certificate) error {
		if ok {
			log.Printf("%s is good!", leaf.Subject.CommonName)
		} else {
			for _, m := range missing {
				log.Printf("%s is missing", m.Subject.CommonName)
				if save {
					err := writeCert(w, m)
					if err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	for _, f := range ci.files {
		ok, leaf, missing, err := checkFile(f, ci.ca)
		if err != nil {
			return err
		}
		err = process(ok, leaf, missing)
		if err != nil {
			return err
		}
	}

	for _, hp := range ci.hostports {
		ok, leaf, missing, err := checkAddr(hp, ci.ca)
		if err != nil {
			return err
		}
		err = process(ok, leaf, missing)
		if err != nil {
			return err
		}
	}
	return nil
}


func (ci *CheckIntermediateCmd) Synopsis() string {
	return "Check a site or a pem certificate file to see if it is trusted by the global cert store. " +
		"This will also provide an option to " +
		"dump any missing intermediates needed to correct the configuration."
}

func checkAddr(addr string, ca *x509.CertPool) (ok bool, leaf *x509.Certificate, missing []*x509.Certificate, err error) {
	hostport := strings.Split(addr, ":")
	if len(hostport) != 2 {
		err = fmt.Errorf("invalid host:port specification: %s", addr)
		return
	}
	var PeerCertificates []*x509.Certificate
	var conn net.Conn
	conn, err = tls.Dial("tcp", addr, &tls.Config{
		ServerName:         hostport[0],
		InsecureSkipVerify: true,
		// Mamually verify certs, catch case where intermediates are missing
		// and dowload them.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates returned from %s", addr)
			}

			PeerCertificates = make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("error parsing cert from %s: %s", addr, err)
				}
				PeerCertificates = append(PeerCertificates, cert)
			}
			var err error
			_, missing, err = verifyChains(PeerCertificates, ca)
			if err != nil {
				return err
			}
			return nil
		},
	})
	if err != nil {
		err = fmt.Errorf("error connecting to host %s: %w", addr, err)
		return
	}
	conn.Close()
	ok = len(missing) == 0
	if len(PeerCertificates) > 0 {
		leaf = PeerCertificates[0]
	}
	return ok, leaf, missing, nil
}

func checkFile(certfile string, ca *x509.CertPool) (ok bool, leafe *x509.Certificate, missing []*x509.Certificate, err error) {
	fbytes, err := ioutil.ReadFile(certfile)
	if err != nil {
		err = fmt.Errorf("error reading file %s: %w", certfile, err)
		return
	}
	certders := decodePemsByType(fbytes, "CERTIFICATE")
	if len(certders) == 0 {
		err = fmt.Errorf("no certificates found in passed bundle %s", certfile)
		return
	}
	certs, err := x509.ParseCertificates(certders)
	if err != nil {
		err = fmt.Errorf("error parsing certificates for file %s: %w", certfile, err)
		return
	}

	if len(certs) == 0 {
		err = fmt.Errorf("no proper ASN1 certificate data found in file %s", certfile)
		return
	}

	_, missing, err = verifyChains(certs, ca)

	if err != nil {
		err = fmt.Errorf("error on verification of file %s: %w", certfile, err)
		return
	}

	ok = len(missing) == 0
	return ok, certs[0], missing, nil
}
