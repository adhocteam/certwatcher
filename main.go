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
	cfg     *ini.File
)

func init() {
	flag.StringVar(&urlFile, "urls", "urls.csv", "path to CSV containing list of URLs to monitor")
	flag.IntVar(&days, "days", 30, "number of days before triggering alert")
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
		r := r

		wg.Add(1)

		go func() {
			errc := make(chan error, 1)

			go func() {
				errc <- check(r[0])
			}()

			select {
			case err := <-errc:
				if err != nil {
					notify(r)
				}

			case <-time.Tick(5 * time.Second):
				log.Println("ERROR: timeout checking", r[0])
			}

			wg.Done()
		}()
	}

	wg.Wait()

	// fin
	os.Exit(0)
}

func check(host string) error {
	log.Printf("check: host: %s", host)
	// connect to host
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}

	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return err
	}

	for _, cert := range conn.ConnectionState().PeerCertificates {
		// log.Printf("check: %s certificate for host %s expires after %s (%s)", host, cert.Subject.Names, cert.NotAfter, time.Until(cert.NotAfter))

		if time.Until(cert.NotAfter) < time.Duration(days)*time.Hour*24 {
			return errors.New("expiring")
		}

		if time.Now().After(cert.NotAfter) {
			return errors.New("expired")
		}
	}

	return nil
}

func notify(r []string) {
	log.Println("notify", r)

	auth := smtp.PlainAuth("",
		cfg.Section("certwatcher").Key("username").String(),
		cfg.Section("certwatcher").Key("password").String(),
		cfg.Section("certwatcher").Key("host").String(),
	)

	to := []string{cfg.Section("certwatcher").Key("rcpt").String()}
	msg := []byte(strings.Join([]string{fmt.Sprintf("Subject: %s certificate expiring soon: %s", cfg.Section("certwatcher").Key("subjectprefix").String(), r[1]),
		"",
		fmt.Sprintf("The SSL certificate for the host %s (%s) is expiring in less than %d days.", r[0], r[1], days),
		"",
		"Please take appropriate action!",
	},
		"\r\n",
	))

	// fmt.Println(string(msg))

	err := smtp.SendMail(cfg.Section("certwatcher").Key("host").String()+":587", auth, cfg.Section("certwatcher").Key("from").String(), to, msg)
	if err != nil {
		log.Fatalf("ERROR: could not send email: %s", err)
	}

	log.Printf("success: sent notification about %s to: %s", r[1], to)

	return
}
