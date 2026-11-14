package cmd

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"howett.net/plist"
)

// setting is one entry of a certificate's trustSettings array.  an empty
// policy leaves kSecTrustSettingsPolicyName out, which is how security(1)
// writes an unscoped setting, and resultAbsent leaves out the result key,
// which is optional.
type setting struct {
	policy string
	result int
}

const resultAbsent = -1

// domain maps a fingerprint to its settings.  a nil slice leaves the
// trustSettings key out of the entry altogether, which is how the roots apple
// ships are exported; an empty slice writes an empty array.
type domain map[string][]setting

// toPlist renders d the way `security trust-settings-export` does, including
// the fields we don't read, and parses it back.
func (d domain) toPlist(t *testing.T) trustSettingsPlist {
	t.Helper()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>trustList</key><dict>`)
	for fp, settings := range d {
		fmt.Fprintf(&b, `<key>%s</key><dict>
<key>issuerName</key><data>AAAA</data>
<key>modDate</key><date>2024-01-01T00:00:00Z</date>
<key>serialNumber</key><data>AQ==</data>`, fp)
		if settings != nil {
			b.WriteString(`<key>trustSettings</key><array>`)
			for _, s := range settings {
				b.WriteString(`<dict><key>kSecTrustSettingsPolicy</key><data>AAAA</data>`)
				if s.policy != "" {
					fmt.Fprintf(&b, `<key>kSecTrustSettingsPolicyName</key><string>%s</string>`, s.policy)
				}
				if s.result != resultAbsent {
					fmt.Fprintf(&b, `<key>kSecTrustSettingsResult</key><integer>%d</integer>`, s.result)
				}
				b.WriteString(`</dict>`)
			}
			b.WriteString(`</array>`)
		}
		b.WriteString(`</dict>`)
	}
	b.WriteString(`</dict><key>trustVersion</key><integer>1</integer></dict></plist>`)

	var ts trustSettingsPlist
	if _, err := plist.Unmarshal([]byte(b.String()), &ts); err != nil {
		t.Fatalf("parsing generated plist: %s", err)
	}
	return ts
}

func fingerprint(c *x509.Certificate) string {
	return strings.ToUpper(hex.EncodeToString(sha1Sum(c.Raw)))
}

func TestTrustSettingsTrusts(t *testing.T) {
	cert := newCert(t, certOpts{cn: "Some Root", isCA: true}).cert
	fp := fingerprint(cert)

	// the domains are user, admin, system: most specific first.
	tests := []struct {
		name                string
		user, admin, system domain
		want                bool
	}{
		{
			name: "not mentioned anywhere",
			want: false,
		},
		{
			name:   "shipped root with no settings key",
			system: domain{fp: nil},
			want:   true,
		},
		{
			name:   "empty settings array",
			system: domain{fp: {}},
			want:   true,
		},
		{
			// SecTrustSettings.h: a missing result defaults to trust root.
			name:   "setting without a result",
			system: domain{fp: {{"sslServer", resultAbsent}}},
			want:   true,
		},
		{
			name:   "unscoped setting without a result",
			system: domain{fp: {{"", resultAbsent}}},
			want:   true,
		},
		{
			name:   "non tls setting without a result",
			system: domain{fp: {{"SMIME", resultAbsent}}},
			want:   false,
		},
		{
			name:   "trust root for ssl",
			system: domain{fp: {{"sslServer", trustResultTrustRoot}}},
			want:   true,
		},
		{
			name:   "trust as root for basic x509",
			system: domain{fp: {{"basicX509", trustResultTrustAsRoot}}},
			want:   true,
		},
		{
			name:   "unscoped trust",
			system: domain{fp: {{"", trustResultTrustRoot}}},
			want:   true,
		},
		{
			name:   "only trusted for a non tls policy",
			system: domain{fp: {{"SMIME", trustResultTrustRoot}}},
			want:   false,
		},
		{
			name:   "denied",
			system: domain{fp: {{"sslServer", trustResultDeny}}},
			want:   false,
		},
		{
			name:   "user deny overrides system trust",
			user:   domain{fp: {{"sslServer", trustResultDeny}}},
			system: domain{fp: nil},
			want:   false,
		},
		{
			name:   "unscoped user deny overrides system trust",
			user:   domain{fp: {{"", trustResultDeny}}},
			system: domain{fp: nil},
			want:   false,
		},
		{
			name:   "admin trust overrides system deny",
			admin:  domain{fp: {{"sslServer", trustResultTrustAsRoot}}},
			system: domain{fp: {{"sslServer", trustResultDeny}}},
			want:   true,
		},
		{
			name:  "user deny beats admin trust",
			user:  domain{fp: {{"sslServer", trustResultDeny}}},
			admin: domain{fp: {{"sslServer", trustResultTrustRoot}}},
			want:  false,
		},
		{
			name:   "user entry for another policy falls through to system",
			user:   domain{fp: {{"SMIME", trustResultDeny}}},
			system: domain{fp: nil},
			want:   true,
		},
		{
			name:   "unspecified result falls through to system",
			admin:  domain{fp: {{"sslServer", trustResultUnspecified}}},
			system: domain{fp: nil},
			want:   true,
		},
		{
			name:   "first applicable setting wins",
			system: domain{fp: {{"SMIME", trustResultDeny}, {"sslServer", trustResultTrustRoot}, {"basicX509", trustResultDeny}}},
			want:   true,
		},
		{
			name:   "another certificate's entry",
			system: domain{"0000000000000000000000000000000000000000": nil},
			want:   false,
		},
		{
			// exports key the trust list by upper case hex.
			name:   "lower case fingerprint doesn't match",
			system: domain{strings.ToLower(fp): nil},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := trustSettings{tt.user.toPlist(t), tt.admin.toPlist(t), tt.system.toPlist(t)}
			if got := ts.trusts(cert); got != tt.want {
				t.Errorf("trusts() = %v, want %v", got, tt.want)
			}
		})
	}
}
