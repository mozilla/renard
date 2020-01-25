/*Package renard implements the RENARD signature scheme

Renard (RNR) is a signature scheme designed to provide strong integrity
guarantees on files. It is based on COSE and developed for Firefox add-ons
(web extensions) and updates.

The binary representation of an RNR signature is a COSE_Sign structure
stored in a signing block inserted in the ZIP or MAR envelope of a file,
immediately before the Central Directory section (similar to Android’s APKv2).
This method allows clients to verify signatures with minimal parsing of the
archive, while retaining a valid archive that can be decompressed using
standard tools.

A signer receives an unsigned file, inserts needed metadata inside the
file, then signs the SHA256 hash of the outer envelope using P-256.
The signature block is stored in a COSE document and inserted in the
outer envelope.

A verifier receives a signed file, extracts the signature block from the
file, calculates the SHA256 hash of the outer envelope (excluding the
signature block) and verifies the signature using the public key of the
end-entity certificate stored in the COSE document. The verifier then
checks the certificate chain, signed timestamp, and root against a local
truststore.

*/
package renard // import "go.mozilla.org/renard"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"go.mozilla.org/cose"
)

const (
	coseTimestampHeaderLabel = "timestamps"
	coseX5ChainHeaderLabel   = "x5chain"
)

// SignMessage is the document that contains signatures and timestamps
// that protect a file. A user of the Renard scheme initializes a new
// SignMessage, populates it, then inserts it into a file according to
// its format. The raw representation of a SignMessage follows the
// COSE_Sign specification from rfc8152.
type SignMessage struct {
	Hashes           map[crypto.Hash][]byte // hashes of signable data indexed by hash algorithm
	Timestamps       []Timestamp            // array of rfc3161 timestamps
	Payload          []byte
	Signatures       []Signature
	CounterSignature CounterSignature

	coseMsg      *cose.SignMessage
	coseMsgBytes []byte
	isFinalized  bool
	fileFormat   FormatIdentifier
	rand         io.Reader // rand is a CSPRNG from crypto/rand (default) or set to a specific reader (like an hsm)
	signableData *bytes.Reader
	encoder      Encoder
}

// A Signature is an authority-issued signature of the hash of the signed file
type Signature struct {
	Algorithm *cose.Algorithm
	CertChain []*x509.Certificate
	coseSig   *cose.Signature
	signer    *cose.Signer
}

// CounterSignature is an optional signature that can be applied
// after the main signatures are issued to allow a 3rd party to add
// additional trust to a given artifact
type CounterSignature interface{}

// NewSignMessage constructs an empty SignMessage
func NewSignMessage() *SignMessage {
	msg := new(SignMessage)
	msg.Hashes = make(map[crypto.Hash][]byte)
	msg.rand = rand.Reader
	return msg
}

// SetRng configures the signers to use a different
// random number generator than the default from crypto/rand
func (msg *SignMessage) SetRng(rng io.Reader) {
	msg.rand = rng
}

// AddTimestamp adds a rfc3161 signed timestamp retrieved an authority
// to a SignMessage.
//
// You can use any compliant public authority, such as
// http://timestamp.digicert.com or http://timestamp.comodoca.com/, as long
// as their roots are trusted by the system.
func (msg *SignMessage) AddTimestamp(server string) error {
	if msg.isFinalized {
		return errors.New("message is already finalized, adding timestamps is not possible as it breaks signatures")
	}
	if msg.Payload == nil {
		return errors.New("message payload is not set")
	}
	h256 := sha256.Sum256(msg.Payload)
	ts, err := requestTimestampFromTSA(server, h256[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to request timestamp from tsa: %w", err)
	}
	msg.Timestamps = append(msg.Timestamps, *ts)
	return nil
}

// PrepareSignature takes a private key and chain of certificates (ordered from end-entity to root)
// and prepares a signature that will sign the message when finalized.
//
// While this function takes a full chain, for verification purpose, the root certificate
// is not included in the final signature and is assumed to be known to verifiers.
//
// The signing algorithm is determined by the key type. RSA keys get PS256, ECDSA
// keys get ES256 for P-256 and ES384 for P-384. No other curves are supported.
func (msg *SignMessage) PrepareSignature(signer crypto.Signer, chain []*x509.Certificate) (err error) {
	if msg.isFinalized {
		return errors.New("message is already finalized, adding signers is not permitted")
	}
	if msg.Payload == nil {
		return errors.New("message payload is not set")
	}
	var sig Signature
	sig.coseSig = cose.NewSignature()

	// find out the cose algorithm based on the priv key type
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		sig.Algorithm = cose.PS256
	case *ecdsa.PublicKey:
		switch signer.Public().(*ecdsa.PublicKey).Params().Name {
		case "P-256":
			sig.Algorithm = cose.ES256
		case "P-384":
			sig.Algorithm = cose.ES384
		default:
			return fmt.Errorf("unsupported curve %s", signer.Public().(*ecdsa.PublicKey).Params().Name)
		}
	default:
		return fmt.Errorf("unsupported key type %t", signer.Public())
	}
	sig.coseSig.Headers.Protected["alg"] = sig.Algorithm.Name

	// make sure the certificate chain is properly constructed,
	err = validateCertChain(chain)
	if err != nil {
		return err
	}
	// then store each cert DER except the root into an array
	var derChain [][]byte
	for i := 0; i < len(chain)-1; i++ {
		derChain = append(derChain, chain[i].Raw[:])
	}
	sig.coseSig.Headers.Protected[coseX5ChainHeaderLabel] = derChain

	sig.signer, err = cose.NewSignerFromKey(sig.Algorithm, signer.(crypto.PrivateKey))
	if err != nil {
		return err
	}
	msg.Signatures = append(msg.Signatures, sig)
	return nil
}

func validateCertChain(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return errors.New("certificate chain cannot have less than 2 certificates (an end-entity and a root)")
	}
	roots := x509.NewCertPool()
	inters := x509.NewCertPool()
	// the last cert in the chain must be the root
	roots.AddCert(chain[len(chain)-1])
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if len(chain) > 2 {
		// for chains greater than 2, add all intermediates to
		// the intermediate certpool in the verify options
		for i := 1; i < len(chain)-1; i++ {
			opts.Intermediates.AddCert(chain[i])
		}
	}
	// now verify the chain starting at the end-entity,
	// which must be the first cert
	_, err := chain[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to verify end-entity chain to root: %w", err)
	}
	return nil
}

// Finalize signs a message with all the configured cose signers and encodes it
// into a COSE_Sign object according to https://tools.ietf.org/html/rfc8152#section-4.1
//
// A finalized message can no longer be modified, but  counter signatures can still be added.
func (msg *SignMessage) Finalize() (err error) {
	if msg.isFinalized {
		return fmt.Errorf("cannot finalize a message that's already finalized")
	}

	// we need to construct a cose.SignMessage from al the data we have in
	// our SignMessage. First we copy the payload, then the signatures, then
	// the signers. The signers need to map to the signatures 1:1, but in 2
	// separate slices.
	var signers []cose.Signer
	msg.coseMsg = cose.NewSignMessage()
	msg.coseMsg.Payload = msg.Payload
	for _, sig := range msg.Signatures {
		msg.coseMsg.AddSignature(sig.coseSig)
		signers = append(signers, *sig.signer)
	}

	// add the timestamps to the top-level headers of the cose signmessage
	if len(msg.Timestamps) > 0 {
		var timestamps [][]byte
		for _, ts := range msg.Timestamps {
			timestamps = append(timestamps, ts.Raw)
		}
		msg.coseMsg.Headers.Protected[coseTimestampHeaderLabel] = timestamps
	}

	err = msg.coseMsg.Sign(msg.rand, nil, signers)
	if err != nil {
		return fmt.Errorf("failed to sign final message: %w", err)
	}

	// the signature is detached so the payload is always empty
	msg.coseMsg.Payload = nil
	msg.coseMsgBytes, err = cose.Marshal(msg.coseMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal cose message: %w", err)
	}
	msg.isFinalized = true
	return nil
}

// Parse parses a binary cose signature into a renard sign message.
func (msg *SignMessage) ParseCoseSignMsg(coseMsg []byte) (err error) {
	if msg.isFinalized {
		return fmt.Errorf("message is already finalized and new cose signatures cannot be parsed into it")
	}
	parsedCoseMsg, err := cose.Unmarshal(coseMsg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal cose message: %w", err)
	}
	cMsg := parsedCoseMsg.(cose.SignMessage)
	msg.coseMsg = &cMsg

	// Parse the timestamps
	if timestamps, ok := msg.coseMsg.Headers.Protected[coseTimestampHeaderLabel]; ok {
		tsArray, ok := timestamps.([]interface{})
		if !ok {
			return fmt.Errorf("failed to decode timestamps as an array")
		}
		for i, timestamp := range tsArray {
			tsBytes, ok := timestamp.([]byte)
			if !ok {
				return fmt.Errorf("failed to decode %d timestamp as a byte sequence", i)
			}
			// timestamp header found, parse them
			parsedTs, err := parseTimestamp(tsBytes)
			if err != nil {
				return fmt.Errorf("failed to parse timestamps: %w", err)
			}
			msg.Timestamps = append(msg.Timestamps, *parsedTs)
		}
	}

	// Parse the signatures
	for i, coseSig := range msg.coseMsg.Signatures {
		var sig Signature
		algValue, ok := coseSig.Headers.Protected[cose.GetCommonHeaderTagOrPanic("alg")]
		if !ok {
			return fmt.Errorf("missing 'alg' protected header in cose signature %d, cannot determine signing algorithm", i)
		}
		if _, ok = algValue.(int); !ok {
			return fmt.Errorf("in signature %d, 'alg' protected header is invalid, cannot determine signing algorithm", i)
		}
		switch algValue {
		case cose.PS256.Value:
			sig.Algorithm = cose.PS256
		case cose.ES256.Value:
			sig.Algorithm = cose.ES256
		case cose.ES384.Value:
			sig.Algorithm = cose.ES384
		default:
			return fmt.Errorf("in signature %d, 'alg' header value %d doesn't match any known algorithm", i, algValue)
		}
		derCerts, ok := coseSig.Headers.Protected[coseX5ChainHeaderLabel]
		if !ok {
			return fmt.Errorf("missing 'x5chain' protected header in cose signature %d, cannot access certificate chain", i)
		}
		if _, ok = derCerts.([]interface{}); !ok {
			return fmt.Errorf("in signature %d, 'x5chain' protected header is not an array, cannot extract certificate chain", i)
		}
		var derChain []byte
		for j, cert := range derCerts.([]interface{}) {
			derCert, ok := cert.([]byte)
			if !ok {
				return fmt.Errorf("in signature %d, certificate %d is not in DER form", i, j)
			}
			derChain = append(derChain, derCert...)
		}
		sig.CertChain, err = x509.ParseCertificates(derChain)
		if err != nil {
			return fmt.Errorf("in signature %d, failed to parse DER certificate chain: %w", i, err)
		}
		sig.coseSig = &coseSig
		msg.Signatures = append(msg.Signatures, sig)
	}
	msg.isFinalized = true
	return
}

// VerifyTimestamps verify all the signed timestamps stored in a SignMessage
// by chaining their certs to a truststore in argument, and verifying the
// hash of the message payload matches the hash message in the timestamp.
func (msg *SignMessage) VerifyTimestamps(certpool *x509.CertPool) error {
	if !msg.isFinalized {
		return errors.New("message is not finalized, cannot verify timestamps")
	}
	if msg.Payload == nil {
		return errors.New("message payload is not set, cannot verify timestamps")
	}
	h256 := sha256.Sum256(msg.Payload)
	for i, ts := range msg.Timestamps {
		err := verifyTimestamp(ts.Raw, h256[:], certpool)
		if err != nil {
			return fmt.Errorf("timestamp %d failed verification: %w", i, err)
		}
	}
	return nil
}

// VerifySignatures verifies each of the signatures stored in a SignMessage
// and makes sure the certificates chain to roots in the provided truststore.
//
// Certificate expiration is checked based on the time of issuance of the
// first signed timestamp listed in the SignMessage, not based on the current
// time. In practice, it means signatures are considered valid as long as
// certificates were valid at the time of issuance of the signature.
//
// If no timestamps are available, certificate expiration is evaluated on
// current time.
func (msg *SignMessage) VerifySignatures(localRoots *x509.CertPool) error {
	if !msg.isFinalized {
		return errors.New("message is not finalized, cannot verify signatures")
	}
	if msg.Payload == nil {
		return errors.New("message payload is not set, cannot verify signatures")
	}
	var verifiers = []cose.Verifier{}

	// First verify the certificate chains on each of the signatures, and while
	// doing so, store the public key of each end-entity into a list of verifiers
	verificationTime := time.Now()
	if len(msg.Timestamps) > 0 {
		verificationTime = msg.Timestamps[0].Time
	}
	for i, sig := range msg.Signatures {
		if len(sig.CertChain) == 0 {
			return fmt.Errorf("empty certificate chain in signature %d", i)
		}
		inters := x509.NewCertPool()
		opts := x509.VerifyOptions{
			Roots:         localRoots,
			Intermediates: inters,
			CurrentTime:   verificationTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		if len(sig.CertChain) > 1 {
			// for chains greater than 1, add all intermediates to
			// the intermediate certpool in the verify options
			for i := 1; i < len(sig.CertChain); i++ {
				opts.Intermediates.AddCert(sig.CertChain[i])
			}
		}
		// the first cert is the end-entity, start there to verify the chain
		_, err := sig.CertChain[0].Verify(opts)
		if err != nil {
			return fmt.Errorf("in signature %d, failed to verify certificate chain: %w", i, err)
		}
		verifiers = append(verifiers, cose.Verifier{
			PublicKey: sig.CertChain[0].PublicKey,
			Alg:       sig.Algorithm,
		})
	}

	// Second, use the verifiers to check the cose signatures
	msg.coseMsg.Payload = msg.Payload
	err := msg.coseMsg.Verify(nil, verifiers)
	if err != nil {
		return fmt.Errorf("failed to verify COSE signatures: %w", err)
	}
	return nil
}

// Verify handles the entire timestamp and signature verification logic. It first calls
// VerifyTimestamp and passes it the timestampTrustStore, then calls VerifySignatures and
// passes it the signaturesTrustStore.
func (msg *SignMessage) Verify(timestampTrustStore, signaturesTrustStore *x509.CertPool) error {
	err := msg.VerifyTimestamps(timestampTrustStore)
	if err != nil {
		return err
	}
	return msg.VerifySignatures(signaturesTrustStore)
}
