package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		startDate               time.Time // of cert
		daysRemaining           int       // of cert
		checkDaysExpiringWithin int
		err                     error
	}{
		{
			time.Now(),
			31,
			30,
			nil,
		},
		{
			time.Now(),
			30,
			30,
			errExpiringSoon,
		},
		{
			time.Now(),
			29,
			30,
			errExpiringSoon,
		},
		{
			time.Now().Add(time.Hour * 24 * -7),
			-1,
			30,
			errExpired,
		},
	}

	for i, test := range tests {
		cert, err := genTestCert(test.startDate, time.Hour*24*time.Duration(test.daysRemaining))
		if err != nil {
			t.Fatalf("error generating test cert: %v", err)
		}

		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		s.StartTLS()

		_, port, err := net.SplitHostPort(s.Listener.Addr().String())
		if err != nil {
			t.Fatalf("error getting port of test TLS server: %v", err)
		}

		if err := check("127.0.0.1", port, test.checkDaysExpiringWithin, false); err != test.err {
			t.Errorf("%d: want %v, got %v", i, test.err, err)
		}
		s.Close()
	}
}

// Generate a self-signed cert for testing a TLS server. Start date and duration
// of the cert are configurable.
func genTestCert(startDate time.Time, duration time.Duration) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Example Corp"},
		},
		NotBefore:   startDate,
		NotAfter:    startDate.Add(duration),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	hosts := []string{"127.0.0.1", "::1", "example.com"}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tlsCert, nil
}
