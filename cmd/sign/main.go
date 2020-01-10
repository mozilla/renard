package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"go.mozilla.org/renard"
)

func main() {
	msg := renard.NewSignMessage()
	msg.SetFileFormat(renard.Zip)
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	signableInput, err := renard.ExtractSignedSections(input)
	if err != nil {
		panic(err)
	}
	msg.SetPayload(signableInput)

	// make 2 signatures
	for i := 1; i < 2; i++ {
		eePriv, chain, err := makeCertChain()
		if err != nil {
			panic(err)
		}
		err = msg.PrepareSignature(eePriv, chain)
		if err != nil {
			panic(err)
		}
	}
	for _, tsServer := range []string{
		"http://timestamp.digicert.com/",
		"http://timestamp.comodoca.com/",
	} {
		err = msg.AddTimestamp(tsServer)
		if err != nil {
			panic(err)
		}
	}
	err = msg.Finalize()
	if err != nil {
		panic(err)
	}
	coseSig, err := msg.Marshal()
	if err != nil {
		panic(err)
	}
	/*
		jsonMsg, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			panic(err)
		}
	*/
	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(coseSig))
}

func makeCertChain() (eePrivKey *ecdsa.PrivateKey, chain []x509.Certificate, err error) {
	rootKeyName := []byte(fmt.Sprintf("root%d", time.Now().Unix()))
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

	interKeyName := []byte(fmt.Sprintf("inter%d", time.Now().Unix()))
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

	eeKeyName := []byte(fmt.Sprintf("endentity%d", time.Now().Unix()))
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
	chain = []x509.Certificate{*rootCert, *interCert, *eeCert}
	return
}
