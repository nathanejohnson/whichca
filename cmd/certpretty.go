package cmd

// Rendering of x509 certificates in the style of openssl x509 -noout -text.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// errWriter accumulates the first write error so the long series of Fprintf
// calls in writeCertPretty doesn't need to check each one.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

// writeCertPretty writes a human readable rendering of cert, modeled on the
// output of openssl x509 -noout -text.
func writeCertPretty(w io.Writer, cert *x509.Certificate) error {
	ew := &errWriter{w: w}

	sigAlgo := opensslSigAlgoNames[cert.SignatureAlgorithm]
	if sigAlgo == "" {
		sigAlgo = cert.SignatureAlgorithm.String()
	}

	ew.printf("Certificate:\n")
	ew.printf("    Data:\n")
	ew.printf("        Version: %d (%#x)\n", cert.Version, cert.Version-1)
	if cert.SerialNumber.IsInt64() {
		ew.printf("        Serial Number: %d (%#x)\n", cert.SerialNumber, cert.SerialNumber)
	} else {
		ew.printf("        Serial Number:\n")
		ew.printf("            %s\n", strings.ToLower(hexColons(cert.SerialNumber.Bytes())))
	}
	ew.printf("        Signature Algorithm: %s\n", sigAlgo)
	ew.printf("        Issuer: %s\n", formatDN(cert.RawIssuer, cert.Issuer))
	ew.printf("        Validity\n")
	ew.printf("            Not Before: %s\n", formatCertTime(cert.NotBefore))
	ew.printf("            Not After : %s\n", formatCertTime(cert.NotAfter))
	ew.printf("        Subject: %s\n", formatDN(cert.RawSubject, cert.Subject))
	writePublicKeyPretty(ew, cert)
	writeExtensionsPretty(ew, cert)

	ew.printf("    Signature Algorithm: %s\n", sigAlgo)
	ew.printf("    Signature Value:\n")
	writeHexBytes(ew, 8, 18, cert.Signature)

	return ew.err
}

func formatCertTime(t time.Time) string {
	return t.UTC().Format("Jan _2 15:04:05 2006") + " GMT"
}

// formatDN renders a distinguished name the way openssl does: attributes in
// their encoded order, joined with ", ".  It decodes raw (the DER of the name)
// rather than using the parsed pkix.Name, because pkix.Name.ToRDNSequence()
// rebuilds the sequence from typed fields and loses the original ordering.
func formatDN(raw []byte, parsed pkix.Name) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		rdns = parsed.ToRDNSequence()
	}
	var parts []string
	for _, rdn := range rdns {
		for _, atv := range rdn {
			label, ok := dnAttrNames[atv.Type.String()]
			if !ok {
				label = atv.Type.String()
			}
			parts = append(parts, fmt.Sprintf("%s=%v", label, atv.Value))
		}
	}
	return strings.Join(parts, ", ")
}

var dnAttrNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "street",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.17":                   "postalCode",
	"2.5.4.42":                   "GN",
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
}

// opensslSigAlgoNames maps go's algorithm spelling (SHA256-RSA) onto the
// names openssl prints (sha256WithRSAEncryption).
var opensslSigAlgoNames = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA:       "md2WithRSAEncryption",
	x509.MD5WithRSA:       "md5WithRSAEncryption",
	x509.SHA1WithRSA:      "sha1WithRSAEncryption",
	x509.SHA256WithRSA:    "sha256WithRSAEncryption",
	x509.SHA384WithRSA:    "sha384WithRSAEncryption",
	x509.SHA512WithRSA:    "sha512WithRSAEncryption",
	x509.SHA256WithRSAPSS: "rsassaPss",
	x509.SHA384WithRSAPSS: "rsassaPss",
	x509.SHA512WithRSAPSS: "rsassaPss",
	x509.DSAWithSHA1:      "dsaWithSHA1",
	x509.DSAWithSHA256:    "dsa_with_SHA256",
	x509.ECDSAWithSHA1:    "ecdsa-with-SHA1",
	x509.ECDSAWithSHA256:  "ecdsa-with-SHA256",
	x509.ECDSAWithSHA384:  "ecdsa-with-SHA384",
	x509.ECDSAWithSHA512:  "ecdsa-with-SHA512",
	x509.PureEd25519:      "ED25519",
}

// curveOIDNames maps go's curve names onto the short OID names openssl prints
// on its "ASN1 OID:" line.
var curveOIDNames = map[string]string{
	"P-224": "secp224r1",
	"P-256": "prime256v1",
	"P-384": "secp384r1",
	"P-521": "secp521r1",
}

var opensslKeyAlgoNames = map[x509.PublicKeyAlgorithm]string{
	x509.RSA:     "rsaEncryption",
	x509.DSA:     "dsaEncryption",
	x509.ECDSA:   "id-ecPublicKey",
	x509.Ed25519: "ED25519",
}

// writeHexBytes renders b as colon separated hex, perLine bytes per line, each
// line prefixed with indent spaces.
func writeHexBytes(ew *errWriter, indent, perLine int, b []byte) {
	pad := strings.Repeat(" ", indent)
	for i := 0; i < len(b); i += perLine {
		end := i + perLine
		if end > len(b) {
			end = len(b)
		}
		var sb strings.Builder
		for j, c := range b[i:end] {
			if j > 0 {
				sb.WriteByte(':')
			}
			fmt.Fprintf(&sb, "%02x", c)
		}
		if end < len(b) {
			sb.WriteByte(':')
		}
		ew.printf("%s%s\n", pad, sb.String())
	}
}

// hexColons renders b as colon separated hex on a single line, the form
// openssl uses for key identifiers.
func hexColons(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", c)
	}
	return sb.String()
}

func writePublicKeyPretty(ew *errWriter, cert *x509.Certificate) {
	keyAlgo := opensslKeyAlgoNames[cert.PublicKeyAlgorithm]
	if keyAlgo == "" {
		keyAlgo = cert.PublicKeyAlgorithm.String()
	}
	ew.printf("        Subject Public Key Info:\n")
	ew.printf("            Public Key Algorithm: %s\n", keyAlgo)
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		ew.printf("                Public-Key: (%d bit)\n", pk.N.BitLen())
		ew.printf("                Modulus:\n")
		// openssl prints the modulus as a signed integer, so a leading zero
		// byte appears whenever the high bit is set.
		mod := pk.N.Bytes()
		if len(mod) > 0 && mod[0]&0x80 != 0 {
			mod = append([]byte{0}, mod...)
		}
		writeHexBytes(ew, 20, 15, mod)
		ew.printf("                Exponent: %d (%#x)\n", pk.E, pk.E)
	case *ecdsa.PublicKey:
		params := pk.Curve.Params()
		ew.printf("                Public-Key: (%d bit)\n", params.BitSize)
		ew.printf("                pub:\n")
		byteLen := (params.BitSize + 7) / 8
		pub := make([]byte, 0, 1+2*byteLen)
		pub = append(pub, 4) // uncompressed point
		pub = append(pub, pk.X.FillBytes(make([]byte, byteLen))...)
		pub = append(pub, pk.Y.FillBytes(make([]byte, byteLen))...)
		writeHexBytes(ew, 20, 15, pub)
		if oid, ok := curveOIDNames[params.Name]; ok {
			ew.printf("                ASN1 OID: %s\n", oid)
		}
		ew.printf("                NIST CURVE: %s\n", params.Name)
	case ed25519.PublicKey:
		ew.printf("                Public-Key: (%d bit)\n", len(pk)*8)
		ew.printf("                pub:\n")
		writeHexBytes(ew, 20, 15, pk)
	default:
		ew.printf("                <unsupported public key type %T>\n", cert.PublicKey)
	}
}

var (
	oidSubjectKeyID        = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidNameConstraints     = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidCRLDistPoints       = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidAnyPolicy           = asn1.ObjectIdentifier{2, 5, 29, 32, 0}
	oidAuthorityKeyID      = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

var keyUsageNames = []struct {
	usage x509.KeyUsage
	name  string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Non Repudiation"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any Extended Key Usage",
	x509.ExtKeyUsageServerAuth:                     "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                     "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "E-mail Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSec End System",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSec Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSec User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

// extNames gives openssl's display name for an extension OID.  Extensions
// missing from the map are printed by OID, as openssl does.
var extNames = map[string]string{
	"2.5.29.9":                "X509v3 Subject Directory Attributes",
	"2.5.29.14":               "X509v3 Subject Key Identifier",
	"2.5.29.15":               "X509v3 Key Usage",
	"2.5.29.16":               "X509v3 Private Key Usage Period",
	"2.5.29.17":               "X509v3 Subject Alternative Name",
	"2.5.29.18":               "X509v3 Issuer Alternative Name",
	"2.5.29.19":               "X509v3 Basic Constraints",
	"2.5.29.30":               "X509v3 Name Constraints",
	"2.5.29.31":               "X509v3 CRL Distribution Points",
	"2.5.29.32":               "X509v3 Certificate Policies",
	"2.5.29.33":               "X509v3 Policy Mappings",
	"2.5.29.35":               "X509v3 Authority Key Identifier",
	"2.5.29.36":               "X509v3 Policy Constraints",
	"2.5.29.37":               "X509v3 Extended Key Usage",
	"2.5.29.54":               "X509v3 Inhibit Any Policy",
	"1.3.6.1.5.5.7.1.1":       "Authority Information Access",
	"1.3.6.1.5.5.7.1.24":      "TLS Feature",
	"1.3.6.1.4.1.11129.2.4.2": "CT Precertificate SCTs",
	"1.3.6.1.4.1.311.21.7":    "Microsoft certificate template",
	"1.3.6.1.4.1.311.21.10":   "Microsoft Application Policies Extension",
	"2.16.840.1.113730.1.1":   "Netscape Cert Type",
	"2.16.840.1.113730.1.13":  "Netscape Comment",
}

// writeExtensionsPretty walks the extensions in the order they appear in the
// certificate, the way openssl does, printing decoded values for the ones
// crypto/x509 parses for us and a hex dump for everything else.
func writeExtensionsPretty(ew *errWriter, cert *x509.Certificate) {
	if len(cert.Extensions) == 0 {
		return
	}
	ew.printf("        X509v3 extensions:\n")

	for _, ext := range cert.Extensions {
		// crypto/x509 drops the critical bit from its parsed fields, so take
		// the name and the bit from the raw extension.
		name, ok := extNames[ext.Id.String()]
		if !ok {
			name = ext.Id.String()
		}
		if ext.Critical {
			ew.printf("            %s: critical\n", name)
		} else {
			ew.printf("            %s:\n", name)
		}

		switch {
		case ext.Id.Equal(oidKeyUsage):
			var usages []string
			for _, ku := range keyUsageNames {
				if cert.KeyUsage&ku.usage != 0 {
					usages = append(usages, ku.name)
				}
			}
			ew.printf("                %s\n", strings.Join(usages, ", "))

		case ext.Id.Equal(oidExtKeyUsage):
			var usages []string
			for _, eku := range cert.ExtKeyUsage {
				if name, ok := extKeyUsageNames[eku]; ok {
					usages = append(usages, name)
				} else {
					usages = append(usages, fmt.Sprintf("Unknown (%d)", eku))
				}
			}
			for _, oid := range cert.UnknownExtKeyUsage {
				usages = append(usages, oid.String())
			}
			ew.printf("                %s\n", strings.Join(usages, ", "))

		case ext.Id.Equal(oidBasicConstraints):
			line := "CA:FALSE"
			if cert.IsCA {
				line = "CA:TRUE"
			}
			if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
				line += fmt.Sprintf(", pathlen:%d", cert.MaxPathLen)
			}
			ew.printf("                %s\n", line)

		case ext.Id.Equal(oidSubjectKeyID):
			ew.printf("                %s\n", hexColons(cert.SubjectKeyId))

		case ext.Id.Equal(oidAuthorityKeyID):
			// only the key identifier: crypto/x509 discards the optional
			// issuer name and serial that openssl also prints here.
			ew.printf("                %s\n", hexColons(cert.AuthorityKeyId))

		case ext.Id.Equal(oidSubjectAltName):
			var names []string
			for _, d := range cert.DNSNames {
				names = append(names, "DNS:"+d)
			}
			for _, e := range cert.EmailAddresses {
				names = append(names, "email:"+e)
			}
			for _, ip := range cert.IPAddresses {
				names = append(names, "IP Address:"+ip.String())
			}
			for _, u := range cert.URIs {
				names = append(names, "URI:"+u.String())
			}
			ew.printf("                %s\n", strings.Join(names, ", "))

		case ext.Id.Equal(oidNameConstraints):
			writeNameConstraints(ew, "Permitted", cert.PermittedDNSDomains, cert.PermittedEmailAddresses,
				cert.PermittedURIDomains, cert.PermittedIPRanges)
			writeNameConstraints(ew, "Excluded", cert.ExcludedDNSDomains, cert.ExcludedEmailAddresses,
				cert.ExcludedURIDomains, cert.ExcludedIPRanges)

		case ext.Id.Equal(oidCRLDistPoints):
			// crypto/x509 flattens every distribution point into a single
			// list, so we treat each URI as its own point.  That matches
			// openssl for the usual one-name-per-point certificate.
			for _, dp := range cert.CRLDistributionPoints {
				ew.printf("                Full Name:\n")
				ew.printf("                  URI:%s\n", dp)
				ew.printf("\n")
			}

		case ext.Id.Equal(oidCertificatePolicies):
			for _, p := range cert.PolicyIdentifiers {
				if p.Equal(oidAnyPolicy) {
					ew.printf("                Policy: X509v3 Any Policy\n")
					continue
				}
				ew.printf("                Policy: %s\n", p)
			}

		case ext.Id.Equal(oidAuthorityInfoAccess):
			for _, u := range cert.OCSPServer {
				ew.printf("                OCSP - URI:%s\n", u)
			}
			for _, u := range cert.IssuingCertificateURL {
				ew.printf("                CA Issuers - URI:%s\n", u)
			}

		default:
			writeHexBytes(ew, 16, 15, ext.Value)
		}
	}
}

func writeNameConstraints(ew *errWriter, label string, dns, email, uri []string, ips []*net.IPNet) {
	if len(dns) == 0 && len(email) == 0 && len(uri) == 0 && len(ips) == 0 {
		return
	}
	ew.printf("                %s:\n", label)
	for _, d := range dns {
		ew.printf("                  DNS:%s\n", d)
	}
	for _, e := range email {
		ew.printf("                  email:%s\n", e)
	}
	for _, u := range uri {
		ew.printf("                  URI:%s\n", u)
	}
	for _, ip := range ips {
		ew.printf("                  IP:%s\n", ip.String())
	}
}
