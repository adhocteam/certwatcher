package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go/aws"
	log "github.com/sirupsen/logrus"
)

var (
	errExpiringSoon = errors.New("expiring soon")
	errExpired      = errors.New("expired")
)

type Config struct {
	URLs    []string `json:"urls"`
	Days    int      `json:"days"`
	Verbose bool     `json:"verbose"`
	Topic   string   `json:"topic"`
}

func main() {

	cfgPath := flag.String("f", "", "path to json cfg.  this must be passed if running locally or not via lambda")
	flag.Parse()
	if len(*cfgPath) != 0 {
		cfg := parseCfg(*cfgPath)
		checkCerts(cfg)
	} else {
		lambda.Start(handle)
	}
}

func handle(ctx context.Context, event json.RawMessage) {

	var cfg Config
	if err := json.Unmarshal(event, &cfg); err != nil {
		log.Fatalf("Failed to unmarshal event: %v", err)
	}
	failures := checkCerts(cfg)
	notify(ctx, failures, cfg.Topic)
}

func checkCerts(cfg Config) []string {

	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	if len(cfg.URLs) == 0 {
		log.Fatalf("No URLs found in %v", cfg)
	}

	var failures []string
	var wg sync.WaitGroup
	for _, url := range cfg.URLs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := check(url, "443", cfg.Days); err != nil {
				msg := fmt.Sprintf("failed host check %s - %s", url, err)
				log.Errorf(msg)
				failures = append(failures, msg)
			}
		}()
	}

	wg.Wait()
	return failures
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

func notify(ctx context.Context, failures []string, topicArn string) {

	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Println("Couldn't load default configuration. Have you set up your AWS account?")
		fmt.Println(err)
		return
	}
	client := sns.NewFromConfig(awsConfig)
	for _, msg := range failures {
		publishInput := sns.PublishInput{TopicArn: aws.String(topicArn), Message: aws.String(msg)}
		_, err := client.Publish(ctx, &publishInput)
		if err != nil {
			log.Fatalf("Couldn't publish message to topic %v. %v", topicArn, err)
		}
		log.Infof("SNS notification sent: %s -> %s", msg, topicArn)
	}
}

func parseCfg(cfgPath string) Config {
	jsonFile, err := os.Open(cfgPath)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)
	var cfg Config
	json.Unmarshal(byteValue, &cfg)
	return cfg
}
