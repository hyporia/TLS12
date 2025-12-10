package main

import (
	"math/big"
	"os"
	"testing"
	"time"
)

func TestUnmarshalServerCertificate(t *testing.T) {
	raw, err := os.ReadFile("server_certificate_msg.bin")
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	sc, err := unmarshalServerCertificate(raw)
	if err != nil {
		t.Fatalf("unmarshalServerCertificate error: %v", err)
	}

	if len(sc.Certificates) != 3 {
		t.Fatalf("expected 3 certificates, got %d", len(sc.Certificates))
	}

	check := func(idx int, subj, issuer string, serialNumber *big.Int, notBefore, notAfter time.Time) {
		cert := sc.Certificates[idx]
		if cert.Subject.String() != subj {
			t.Errorf("cert %d subject mismatch:\n got:  %s\n want: %s", idx, cert.Subject.String(), subj)
		}
		if cert.Issuer.String() != issuer {
			t.Errorf("cert %d issuer mismatch:\n got:  %s\n want: %s", idx, cert.Issuer.String(), issuer)
		}
		gotSerial := cert.SerialNumber
		if gotSerial.Cmp(serialNumber) != 0 {
			t.Errorf("cert %d serial mismatch:\n got:  %s\n want: %s", idx, gotSerial, serialNumber)
		}
		if !cert.NotBefore.Equal(notBefore) {
			t.Errorf("cert %d NotBefore mismatch:\n got:  %v\n want: %v", idx, cert.NotBefore, notBefore)
		}
		if !cert.NotAfter.Equal(notAfter) {
			t.Errorf("cert %d NotAfter mismatch:\n got:  %v\n want: %v", idx, cert.NotAfter, notAfter)
		}
	}

	mustBeBigInt := func(s string) *big.Int {
		i, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("invalid big.Int literal: %q", s)
		}
		return i
	}

	check(0,
		"CN=*.google.com",
		"CN=WR2,O=Google Trust Services,C=US",
		mustBeBigInt("60394724544825835345752647471744394661"),
		time.Date(2025, 9, 22, 8, 40, 36, 0, time.UTC),
		time.Date(2025, 12, 15, 8, 40, 35, 0, time.UTC),
	)

	check(1,
		"CN=WR2,O=Google Trust Services,C=US",
		"CN=GTS Root R1,O=Google Trust Services LLC,C=US",
		mustBeBigInt("170058220837755766831192027518741805976"),
		time.Date(2023, 12, 13, 9, 0, 0, 0, time.UTC),
		time.Date(2029, 2, 20, 14, 0, 0, 0, time.UTC),
	)

	check(2,
		"CN=GTS Root R1,O=Google Trust Services LLC,C=US",
		"CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE",
		mustBeBigInt("159159747900478145820483398898491642637"),
		time.Date(2020, 6, 19, 0, 0, 42, 0, time.UTC),
		time.Date(2028, 1, 28, 0, 0, 42, 0, time.UTC),
	)
}
