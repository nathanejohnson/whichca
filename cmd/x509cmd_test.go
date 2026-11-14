package cmd

import (
	"slices"
	"testing"
)

func TestNormalizeForm(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "PEM", want: formPEM},
		{in: "pem", want: formPEM},
		{in: "Der", want: formDER},
		{in: "txt", wantErr: true},
	}
	for _, tt := range tests {
		got, err := normalizeForm(tt.in, "inform")
		if (err != nil) != tt.wantErr {
			t.Errorf("normalizeForm(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeForm(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseCerts(t *testing.T) {
	a := newCert(t, certOpts{cn: "a", isCA: true})
	b := newCert(t, certOpts{cn: "b", parent: a})
	keyBlock := []byte("-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----\n")

	tests := []struct {
		name    string
		raw     []byte
		form    string
		want    []string
		wantErr bool
	}{
		{name: "detect pem", raw: pemOf(a.cert), want: []string{"a"}},
		{name: "detect pem bundle", raw: pemOf(a.cert, b.cert), want: []string{"a", "b"}},
		{name: "other pem blocks skipped", raw: append(keyBlock, pemOf(b.cert)...), want: []string{"b"}},
		{name: "detect der", raw: a.cert.Raw, want: []string{"a"}},
		{name: "concatenated der", raw: append(slices.Clone(a.cert.Raw), b.cert.Raw...), want: []string{"a", "b"}},
		{name: "explicit pem", raw: pemOf(a.cert), form: formPEM, want: []string{"a"}},
		{name: "explicit der", raw: a.cert.Raw, form: formDER, want: []string{"a"}},
		{name: "pem without certificates", raw: keyBlock, wantErr: true},
		{name: "der read as pem", raw: a.cert.Raw, form: formPEM, wantErr: true},
		{name: "pem read as der", raw: pemOf(a.cert), form: formDER, wantErr: true},
		{name: "garbage", raw: []byte("hello"), wantErr: true},
		// the caller reports this one, since it knows the input's name.
		{name: "empty", raw: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCerts(tt.raw, tt.form)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := subjects(certs); !slices.Equal(got, tt.want) {
				t.Errorf("certs = %v, want %v", got, tt.want)
			}
		})
	}
}
