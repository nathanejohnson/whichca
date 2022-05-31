//go:build !darwin
// +build !darwin

package cmd

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"unsafe"
)

func CertPoolSnoopable() (bool, []*x509.Certificate, error) {
	systemCA, err := x509.SystemCertPool()
	if err != nil {
		return false, nil, err
	}

	// eww
	v := reflect.ValueOf(systemCA)
	lazyCertsV := v.Elem().FieldByName("lazyCerts")
	switch k := lazyCertsV.Kind(); k {
	case reflect.Slice:
	default:
		return false, nil, fmt.Errorf("invalid type: %s", k.String())
	}
	certs := make([]*x509.Certificate, lazyCertsV.Len())
	for i := 0; i < lazyCertsV.Len(); i++ {
		lcv := lazyCertsV.Index(i)
		if !lcv.IsValid() {
			return false, nil, fmt.Errorf("error indexing lazyCertsV")
		}
		getCertV := lcv.FieldByName("getCert")
		if !lcv.IsValid() {
			return false, nil, fmt.Errorf("invalid getCertV")
		}

		fPtr := reflect.NewAt(getCertV.Type(),
			unsafe.Pointer(getCertV.UnsafeAddr())).
			Elem().Interface().(func() (*x509.Certificate, error))
		crt, err := fPtr()
		if err != nil {
			return false, nil, fmt.Errorf("error from call to getCert: %w", err)
		}
		certs[i] = crt

	}
	return true, certs, nil
}
