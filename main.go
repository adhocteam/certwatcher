package main

import (
	"crypto/tls"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	ini "gopkg.in/ini.v1"
)

var (
	urlFile string
	days    int
	verbose bool
	cfg     *ini.File
)

var (
	errExpiringSoon error = errors.New("expiring soon")
	errExpired            = errors.New("expired")
	errTimeout            = errors.New("timeout connecting to host")
)

func init() {
	flag.StringVar(&urlFile, "urls", "urls.csv", "path to CSV containing list of URLs to monitor")
	flag.IntVar(&days, "days", 30, "number of days before triggering alert")
	flag.BoolVar(&verbose, "v", false, "verbose output")
}

type Host struct {
	Host, Desc string
}

func main() {
	flag.Parse()

	var err error

	// read config
	cfg, err = ini.Load("config.ini")
	if err != nil {
		log.Fatalf("ERROR: could not open config file: %s", err)
	}

	// load list of hosts to watch
	f, err := os.Open(urlFile)
	if err != nil {
		log.Fatalf("ERROR: could not open URL file: %s", err)
	}

	rdr := csv.NewReader(f)
	records, err := rdr.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	for _, r := range records {
		host, desc := r[0], r[1]

		wg.Add(1)

		go func() {
			if err := check(host); err != nil {
				switch err {
				case errExpiringSoon, errExpired:
					notify(host, desc)
					log.Printf("main: sent notifiction for host %s - %s", host, err)
				default:
					log.Printf("main: ERROR: unexpected error checking host %s - %s", host, err)
				}
			}
			wg.Done()
		}()
	}

	wg.Wait()

	// fin
	os.Exit(0)
}

func check(host string) error {
	var conn *tls.Conn

	errc := make(chan error, 1)
	go func() {
		var err error
		conn, err = tls.Dial("tcp", host+":443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			errc <- err
		}

		errc <- nil
	}()

	select {
	case err := <-errc:
		if err != nil {
			return err
		}
	case <-time.Tick(5 * time.Second):
		return errTimeout
	}

	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return err
	}

	for i, cert := range conn.ConnectionState().PeerCertificates {
		if cert.IsCA {
			continue
		}

		if verbose {
			log.Printf("check: %s certificate %d: expires after %s (%s)", host, i, cert.NotAfter, time.Until(cert.NotAfter))
			log.Printf("check: %s certificate %d: issuer: %s", host, i, cert.Issuer.Names)
			log.Printf("check: %s certificate %d: names: %s", host, i, cert.Subject.Names)
			log.Printf("check: %s certificate %d: DNSNames: %s", host, i, cert.DNSNames)
		}

		if time.Until(cert.NotAfter) < time.Duration(days)*time.Hour*24 {
			return errExpiringSoon
		}

		if time.Now().After(cert.NotAfter) {
			return errExpired
		}
	}

	log.Printf("check: %s - certificate is ok", host)

	return nil
}

func notify(host, desc string) {
	if !cfg.Section("certwatcher").Key("sendmail").MustBool() {
		log.Println("notify: refusing to send email due to config.")
		return
	}

	auth := smtp.PlainAuth("",
		cfg.Section("certwatcher").Key("username").String(),
		cfg.Section("certwatcher").Key("password").String(),
		cfg.Section("certwatcher").Key("host").String(),
	)

	to := []string{cfg.Section("certwatcher").Key("rcpt").String()}
	msg := []byte(strings.Join([]string{fmt.Sprintf("Subject: %s certificate expiring soon: %s", cfg.Section("certwatcher").Key("subjectprefix").String(), desc),
		fmt.Sprintf("To: %s", cfg.Section("certwatcher").Key("rcpt").String()),
		"",
		fmt.Sprintf("The SSL certificate for the host %s (%s) is expiring in less than %d days.", host, desc, days),
		"",
		"Please take appropriate action!",
	},
		"\r\n",
	))

	if verbose {
		log.Println("notify: sending host %s expiration notification to %s", host, cfg.Section("certwatcher").Key("rcpt").String())
	}

	err := smtp.SendMail(cfg.Section("certwatcher").Key("host").String()+":587", auth, cfg.Section("certwatcher").Key("from").String(), to, msg)
	if err != nil {
		log.Fatalf("ERROR: could not send email: %s", err)
	}

	return
}
