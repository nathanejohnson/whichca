package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestStringParams(t *testing.T) {
	var sp stringparams
	for _, v := range []string{"a.example:443", "b.example:443,c.example:8443"} {
		if err := sp.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"a.example:443", "b.example:443", "c.example:8443"}; !slices.Equal(sp, want) {
		t.Errorf("stringparams = %q, want %q", sp, want)
	}
}

func TestGlobParams(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.pem", "b.pem", "c.crt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	in := func(name string) string { return filepath.Join(dir, name) }

	tests := []struct {
		name    string
		values  []string
		want    []string
		wantErr bool
	}{
		{name: "plain file", values: []string{in("c.crt")}, want: []string{in("c.crt")}},
		{name: "glob", values: []string{in("*.pem")}, want: []string{in("a.pem"), in("b.pem")}},
		{name: "comma separated", values: []string{in("a.pem") + "," + in("*.crt")}, want: []string{in("a.pem"), in("c.crt")}},
		{name: "repeated flag", values: []string{in("a.pem"), in("b.pem")}, want: []string{in("a.pem"), in("b.pem")}},
		// a path that matches nothing is dropped rather than reported.
		{name: "no match", values: []string{in("missing.pem")}},
		{name: "bad pattern", values: []string{in("[")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gp globparams
			var err error
			for _, v := range tt.values {
				if err = gp.Set(v); err != nil {
					break
				}
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(gp, tt.want) {
				t.Errorf("globparams = %q, want %q", gp, tt.want)
			}
		})
	}
}
