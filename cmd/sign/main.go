package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"go.mozilla.org/renard"
	_ "go.mozilla.org/renard/zip"
)

func main() {
	msg := renard.NewSignMessage()
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	buf := bytes.NewReader(input)
	err = msg.ReadPayload(buf, renard.Zip)
	if err != nil {
		panic(err)
	}
	// make 2 chains of certs and preparing signatures using them
	localCertPool := x509.NewCertPool()
	for i := 1; i <= 2; i++ {
		fmt.Printf("-- preparing signature %d\n", i)
		eePriv, chain, err := makeCertChain()
		if err != nil {
			panic(err)
		}
		err = msg.PrepareSignature(eePriv, chain)
		if err != nil {
			panic(err)
		}
		// we save the roots for verification later
		localCertPool.AddCert(chain[len(chain)-1])
	}
	// request timestamps from two separate TSAs
	for i, tsServer := range []string{
		"http://timestamp.digicert.com/",
		"http://timestamp.comodoca.com/",
	} {
		fmt.Printf("-- requesting timestamp %d from %q\n", i, tsServer)
		err = msg.AddTimestamp(tsServer)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("-- signing and finalizing\n")
	err = msg.Finalize()
	if err != nil {
		panic(err)
	}
	// write the output file to disk
	fd, err := ioutil.TempFile("", "renard")
	if err != nil {
		panic(err)
	}
	err = msg.WritePayload(fd)
	if err != nil {
		panic(err)
	}
	fmt.Println("-- output file written to", fd.Name())

	// Read back the signed file and verify
	fmt.Println("-- reading back", fd.Name())
	input2, err := ioutil.ReadFile(fd.Name())
	if err != nil {
		panic(err)
	}
	buf2 := bytes.NewReader(input2)
	parsedMsg := renard.NewSignMessage()
	err = parsedMsg.ReadPayload(buf2, renard.Zip)
	if err != nil {
		panic(err)
	}
	err = parsedMsg.ReadSignature(buf2, renard.Zip)
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

// helper that generates a certificate chain and returns it ordered from end-entity to root
func makeCertChain() (eePrivKey *ecdsa.PrivateKey, chain []*x509.Certificate, err error) {
	rootKeyName := []byte(fmt.Sprintf("root%d", time.Now().UnixNano()))
	rootPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return
	}
	caTpl := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Mozilla"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Mountain View"},
		},
		NotBefore:             time.Now().AddDate(0, -2, -2), // start 2 months and 2 days ago
		NotAfter:              time.Now().AddDate(30, 0, 0),  // valid for 30 years
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caTpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	caTpl.Subject.CommonName = string(rootKeyName)
	rootCertBytes, err := x509.CreateCertificate(
		rand.Reader, caTpl, caTpl, rootPriv.Public(), rootPriv)
	if err != nil {
		return
	}
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		return
	}

	interKeyName := []byte(fmt.Sprintf("inter%d", time.Now().UnixNano()))
	interPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return
	}
	caTpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	caTpl.Subject.CommonName = string(interKeyName)
	caTpl.NotBefore = time.Now().AddDate(0, -2, -1) // start 2 months and 1 day ago
	caTpl.NotAfter = time.Now().AddDate(10, 0, 0)   // valid for 10 years
	interCertBytes, err := x509.CreateCertificate(
		rand.Reader, caTpl, rootCert, interPriv.Public(), rootPriv)
	if err != nil {
		return
	}
	interCert, err := x509.ParseCertificate(interCertBytes)
	if err != nil {
		return
	}

	eeKeyName := []byte(fmt.Sprintf("endentity%d", time.Now().UnixNano()))
	eePrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	caTpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	caTpl.Subject.CommonName = string(eeKeyName)
	caTpl.NotBefore = time.Now().AddDate(0, -2, -1) // start 2 months and 1 day ago
	caTpl.NotAfter = time.Now().AddDate(1, 0, 0)    // valid for 1 years
	eeCertBytes, err := x509.CreateCertificate(
		rand.Reader, caTpl, interCert, eePrivKey.Public(), interPriv)
	if err != nil {
		return
	}
	eeCert, err := x509.ParseCertificate(eeCertBytes)
	if err != nil {
		return
	}
	chain = []*x509.Certificate{eeCert, interCert, rootCert}
	return
}
