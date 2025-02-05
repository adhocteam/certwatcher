package main

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"errors"
	"flag"
	"net"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
)

var (
	errExpiringSoon = errors.New("expiring soon")
	errExpired      = errors.New("expired")
)

type Config struct {
	UrlFile string `json:"urlFile"`
	Days    int    `json:"days"`
	Verbose bool   `json:"verbose"`
}

func main() {

	urlFile := flag.String("urls", "urls.csv", "path to CSV containing list of URLs to monitor")
	days := flag.Int("days", 30, "number of days before triggering alert")
	local := flag.Bool("l", false, "run locally")
	verbose := flag.Bool("v", false, "verbose output")
	flag.Parse()

	cfg := Config{
		UrlFile: *urlFile,
		Days:    *days,
		Verbose: *verbose,
	}

	if *local {
		checkCerts(cfg)
	} else {
		lambda.Start(handle)
	}

}

func handle(ctx context.Context, cfg Config) {
	checkCerts(cfg)
}

func checkCerts(cfg Config) {

	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	f, err := os.Open(cfg.UrlFile)
	if err != nil {
		log.Fatalf("could not open URL file: %s", err)
	}

	rdr := csv.NewReader(f)
	rdr.FieldsPerRecord = 2
	rdr.Comment = '#'
	records, err := rdr.ReadAll()
	if err != nil {
		log.Fatalf("could not read %s: %s", cfg.UrlFile, err)
	}

	var failed = false
	var wg sync.WaitGroup
	for _, r := range records {
		host, desc := r[0], r[1]
		if desc == "" {
			desc = host
		}

		wg.Add(1)

		go func() {
			defer wg.Done()
			if err := check(host, "443", cfg.Days); err != nil {
				failed = true
				log.Errorf("failed host check %s (%s) - %s", host, desc, err)
			}
		}()
	}

	wg.Wait()
	if failed {
		log.Fatal("Cert Validation Failure")
	}
}

func check(host, port string, days int) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}

	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}

	for i, cert := range conn.ConnectionState().PeerCertificates {
		if cert.IsCA {
			continue
		}

		log.Debugf("check: %s certificate %d: expires after %s (%s)", host, i, cert.NotAfter, time.Until(cert.NotAfter))
		log.Debugf("check: %s certificate %d: issuer: %s", host, i, cert.Issuer.Names)
		log.Debugf("check: %s certificate %d: names: %s", host, i, cert.Subject.Names)
		log.Debugf("check: %s certificate %d: DNSNames: %s", host, i, cert.DNSNames)

		if time.Now().After(cert.NotAfter) {
			return errExpired
		}

		if time.Until(cert.NotAfter) < time.Duration(days)*time.Hour*24 {
			return errExpiringSoon
		}
	}

	log.Infof("check: %s - certificate is ok", host)

	return nil
}
