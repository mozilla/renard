package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"go.mozilla.org/renard"
	_ "go.mozilla.org/renard/zip"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: verify <file>")
	}
	fmt.Println("-- verifying", os.Args[1])
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	buf := bytes.NewReader(input)
	parsedMsg := renard.NewSignMessage()
	err = parsedMsg.ReadPayload(buf, renard.Zip)
	if err != nil {
		panic(err)
	}
	err = parsedMsg.ReadSignature(buf, renard.Zip)
	if err != nil {
		panic(err)
	}
	for i, ts := range parsedMsg.Timestamps {
		fmt.Printf("-- found timestamp %d from %q\n", i, ts.Certificates[0].Issuer.CommonName)
	}
	for i, sig := range parsedMsg.Signatures {
		for j, cert := range sig.CertChain {
			fmt.Printf("-- signature %d certificate %d %s\n", i, j, cert.Subject.CommonName)
		}
	}

	// Verify the signatures of the timestamps and the chain of certificates
	// against the roots stored in the system truststore.
	localCertPool := x509.NewCertPool()
	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	err = parsedMsg.Verify(systemCertPool, localCertPool)
	if err != nil {
		panic(err)
	}
	fmt.Println("-- timestamps & signatures verified")
}
