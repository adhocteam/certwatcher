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
	errExpiringSoon error = errors.New("expiring soon")
	errExpired            = errors.New("expired")
	errTimeout            = errors.New("timeout connecting to host")
)

func main() {
	urlFile := flag.String("urls", "/etc/certwatcher/urls.csv", "path to CSV containing list of URLs to monitor")
	iniFile := flag.String("config", "/etc/certwatcher/config.ini", "path to config.ini")
	days := flag.Int("days", 30, "number of days before triggering alert")
	verbose := flag.Bool("v", false, "verbose output")

	flag.Parse()

	// read config
	cfg, err := ini.Load(*iniFile)
	if err != nil {
		log.Fatalf("could not open config file: %s", err)
	}

	// load list of hosts to watch
	f, err := os.Open(*urlFile)
	if err != nil {
		log.Fatalf("could not open URL file: %s", err)
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
			defer wg.Done()
			if err := check(host, "443", *days, *verbose); err != nil {
				switch err {
				case errExpiringSoon, errExpired:
					notify(host, desc, cfg, *days, err, *verbose)
					log.Printf("main: sent notification for host %s - %s", host, err)
				default:
					log.Printf("main: ERROR: unexpected error checking host %s - %s", host, err)
				}
			}
		}()
	}

	wg.Wait()
}

func check(host, port string, days int, verbose bool) error {
	var conn *tls.Conn

	errc := make(chan error, 1)
	go func() {
		var err error
		conn, err = tls.Dial("tcp", host+":"+port, &tls.Config{
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

		if time.Now().After(cert.NotAfter) {
			return errExpired
		}

		if time.Until(cert.NotAfter) < time.Duration(days)*time.Hour*24 {
			return errExpiringSoon
		}
	}

	log.Printf("check: %s - certificate is ok", host)

	return nil
}

func notify(host, desc string, cfg *ini.File, days int, err error, verbose bool) {
	section := cfg.Section("certwatcher")

	if !section.Key("sendmail").MustBool() {
		log.Println("notify: refusing to send email due to config.")
		return
	}

	port := "587"
	if section.Key("port").String() != "" {
		port = section.Key("port").String()
	}
	mailhost := section.Key("host").String()

	auth := smtp.PlainAuth("",
		section.Key("username").String(),
		section.Key("password").String(),
		mailhost,
	)

	to := []string{section.Key("rcpt").String()}
	var subject, body string
	if err == errExpiringSoon {
		subject = fmt.Sprintf("Subject: %s certificate expiring soon: %s", section.Key("subjectprefix").String(), desc)
		body = fmt.Sprintf("The SSL certificate for the host %s (%s) is expiring in less than %d days.", host, desc, days)
	} else if err == errExpired {
		subject = fmt.Sprintf("Subject: %s certificate has expired! %s", section.Key("subjectprefix").String(), desc)
		body = fmt.Sprintf("The SSL certificate for the host %s (%s) has expired!", host, desc)
	}
	msg := []byte(strings.Join([]string{subject,
		fmt.Sprintf("To: %s", strings.Join(to, ", ")),
		fmt.Sprintf("From: %s", section.Key("from").String()),
		"",
		body,
		"",
		"Please take appropriate action!",
	},
		"\r\n",
	))

	if verbose {
		log.Printf("notify: sending host %s expiration notification to %s", host, section.Key("rcpt").String())
	}

	if err := smtp.SendMail(mailhost+":"+port, auth, section.Key("from").String(), to, msg); err != nil {
		log.Fatalf("could not send email: %s", err)
	}
}
