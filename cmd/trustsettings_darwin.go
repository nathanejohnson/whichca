package cmd

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"howett.net/plist"
)

// kSecTrustSettingsResult values.  anything else means the setting doesn't
// make the certificate an anchor.
const (
	trustResultInvalid = iota
	trustResultTrustRoot
	trustResultTrustAsRoot
	trustResultDeny
	trustResultUnspecified
)

// policies that matter for validating a TLS chain.  a setting scoped to, say,
// SMIME alone says nothing about whether we should trust this root here.
var tlsTrustPolicies = map[string]bool{
	"":          true, // unscoped, applies to everything
	"basicX509": true,
	"sslServer": true,
}

// trustSettingsPlist mirrors the shape of `security trust-settings-export`.
// the trustList is keyed by the certificate's SHA-1 fingerprint in upper case
// hex, which is what lets us match entries back to certificates exactly.
type trustSettingsPlist struct {
	TrustList map[string]struct {
		TrustSettings []struct {
			PolicyName string `plist:"kSecTrustSettingsPolicyName"`
			Result     *int   `plist:"kSecTrustSettingsResult"`
		} `plist:"trustSettings"`
	} `plist:"trustList"`
}

// trustSettings is the merged view of the three trust domains, in the order
// they take precedence.
type trustSettings []trustSettingsPlist

// trusts reports whether the platform treats cert as a trust anchor.
//
// the domains are consulted most specific first -- user, then admin, then
// system -- and the first one holding an entry for this certificate decides,
// which is how an admin or user setting overrides what apple ships.  a
// certificate no domain mentions at all is simply present in a keychain, not
// trusted.
func (ts trustSettings) trusts(cert *x509.Certificate) bool {
	fp := strings.ToUpper(hex.EncodeToString(sha1Sum(cert.Raw)))
	for _, domain := range ts {
		entry, ok := domain.TrustList[fp]
		if !ok {
			continue
		}
		// no settings recorded means "trusted for everything", which is how
		// the roots apple ships are represented.
		if len(entry.TrustSettings) == 0 {
			return true
		}
		for _, setting := range entry.TrustSettings {
			if !tlsTrustPolicies[setting.PolicyName] {
				continue
			}
			// the result key is optional.  SecTrustSettings.h documents
			// trust root as its default when it's left out.
			result := trustResultTrustRoot
			if setting.Result != nil {
				result = *setting.Result
			}
			switch result {
			case trustResultTrustRoot, trustResultTrustAsRoot:
				return true
			case trustResultDeny:
				return false
			}
		}
		// an entry that only covers other policies tells us nothing, so keep
		// looking in the less specific domains.
	}
	return false
}

func sha1Sum(b []byte) []byte {
	sum := sha1.Sum(b)
	return sum[:]
}

// loadTrustSettings exports each trust domain and parses it.  they're listed
// most specific first so trusts() can stop at the first match.
func loadTrustSettings() (trustSettings, error) {
	dir, err := os.MkdirTemp("", "whichca-trust")
	if err != nil {
		return nil, fmt.Errorf("error creating temp dir for trust settings: %w", err)
	}
	defer os.RemoveAll(dir)

	var ts trustSettings
	// user first, then admin, then system: most specific wins.
	for i, args := range [][]string{{}, {"-d"}, {"-s"}} {
		path := filepath.Join(dir, fmt.Sprintf("%d.plist", i))
		domain, err := exportTrustSettings(path, args...)
		if err != nil {
			return nil, err
		}
		ts = append(ts, domain)
	}
	return ts, nil
}

func exportTrustSettings(path string, args ...string) (trustSettingsPlist, error) {
	var settings trustSettingsPlist

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	cmdArgs := append([]string{"trust-settings-export"}, args...)
	cmdArgs = append(cmdArgs, path)
	out, err := exec.CommandContext(ctx, "security", cmdArgs...).CombinedOutput()
	if err != nil {
		// an empty domain is normal -- plenty of machines have no admin or
		// user trust settings at all -- and security(1) reports that as a
		// failure to export.  treat it as the empty set rather than an error.
		if _, statErr := os.Stat(path); statErr != nil {
			return settings, nil
		}
		return settings, fmt.Errorf("error exporting trust settings (security %s): %w: %s",
			strings.Join(cmdArgs, " "), err, out)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return settings, fmt.Errorf("error reading exported trust settings: %w", err)
	}
	if len(raw) == 0 {
		return settings, nil
	}
	if _, err = plist.Unmarshal(raw, &settings); err != nil {
		return settings, fmt.Errorf("error parsing exported trust settings: %w", err)
	}
	return settings, nil
}
