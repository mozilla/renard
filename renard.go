/*Package renard implements the RENARD signature format

Renard (RNR) is a signature format designed to provide strong integrity
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
	"os"
	"time"

	"go.mozilla.org/cose"
)

const (
	// timestamp cose header allocated in private range
	coseTimestampHeaderLabel = -718357482

	// x5chain cose header registered at
	// https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
	coseX5ChainHeaderLabel = 33
)

// SignMessage is the document that contains signatures and timestamps
// that protect a file. A user of the Renard format initializes a new
// SignMessage, populates it, then inserts it into a file according to
// its format. The raw representation of a SignMessage follows the
// COSE_Sign specification from rfc8152.
type SignMessage struct {
	Hashes           map[crypto.Hash][]byte // hashes of signable data indexed by hash algorithm
	Payload          []byte
	Signatures       []Signature
	CounterSignature CounterSignature

	coseMsg                             *cose.SignMessage
	coseMsgBytes                        []byte
	hasFinalizedSignatures, isFinalized bool
	fileFormat                          FormatIdentifier
	rand                                io.Reader // rand is a CSPRNG from crypto/rand (default) or set to a specific reader (like an hsm)
	signableData                        *bytes.Reader
	encoder                             Encoder
}

// A Signature is an authority-issued signature of the hash of the signed file
type Signature struct {
	Algorithm      *cose.Algorithm
	CertChain      []*x509.Certificate
	Timestamps     []Timestamp // array of rfc3161 timestamps
	SignatureBytes []byte
	coseSig        *cose.Signature
	signer         *cose.Signer
	tsaServers     []string
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

// AddSignature takes a private key, chain of certificates (ordered from end-entity to root)
// and a list of timestamping authority servers, then prepares a signature that will sign and
// timestamp the message when finalized.
//
// While this function takes a full chain, for verification purpose, the root certificate
// is not included in the final signature and is assumed to be known to verifiers.
//
// The signing algorithm is determined by the key type. RSA keys get PS256, ECDSA
// keys get ES256 for P-256 and ES384 for P-384. No other curves are supported.
//
// A list of valid and trusted TSA servers is kept in WellKnownTSA.
func (msg *SignMessage) AddSignature(signer crypto.Signer, chain []*x509.Certificate, tsaServers []string) (err error) {
	if msg.isFinalized {
		return errors.New("message is already finalized, adding signers is not permitted")
	}
	if msg.Payload == nil {
		return errors.New("message payload is not set")
	}
	var sig Signature
	sig.coseSig = cose.NewSignature()

	// store the list of TSA servers to be used for timestamping
	// once signatures are issued. This is done when finalizing.
	if len(tsaServers) == 0 {
		return fmt.Errorf("at least one tsa server is required for timestamping")
	}
	sig.tsaServers = tsaServers

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

// validateCertChain checks that a provided chain of x509 certificates
// verifies itself and is properly ordered from end-entity to
// intermediate to root.
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

// Finalize performs the signature process with all the configured cose signers,
// issues timestamps on all of the signatures, then marshals the signature message
// into a COSE message ready for writing to an output.
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
	err = msg.coseMsg.Sign(msg.rand, nil, signers)
	if err != nil {
		return fmt.Errorf("failed to compute cose signatures: %w", err)
	}
	// the signature is detached so the payload is always empty
	msg.coseMsg.Payload = nil

	// store cose signature bytes into the parsed struct
	for i := range msg.Signatures {
		msg.Signatures[i].SignatureBytes = msg.coseMsg.Signatures[i].SignatureBytes
	}
	err = msg.timestampSignatures()
	if err != nil {
		return fmt.Errorf("failed to timestamp signatures: %w", err)
	}
	msg.coseMsgBytes, err = cose.Marshal(msg.coseMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal cose message: %w", err)
	}
	msg.isFinalized = true
	return nil
}

// timestampSignatures adds a rfc3161 signed timestamp
// to each Cose signatures existing on a message.
func (msg *SignMessage) timestampSignatures() error {
	for i, sig := range msg.Signatures {
		// take the hash of the signature bytes as the timestamp payload
		h256 := sha256.Sum256(sig.SignatureBytes)
		for _, tsaServer := range sig.tsaServers {
			ts, err := requestTimestampFromTSA(tsaServer, h256[:], crypto.SHA256)
			if err != nil {
				return fmt.Errorf("failed to request timestamp from tsa %q: %w", tsaServer, err)
			}
			msg.Signatures[i].Timestamps = append(msg.Signatures[i].Timestamps, *ts)
		}
		var rawTimestamps [][]byte
		for _, timestamp := range msg.Signatures[i].Timestamps {
			rawTimestamps = append(rawTimestamps, timestamp.Raw)
		}
		msg.coseMsg.Signatures[i].Headers.Unprotected[coseTimestampHeaderLabel] = rawTimestamps
	}
	return nil
}

// ParseCoseSignMsg parses a binary cose signature into a renard sign message.
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

	// Parse the signatures
	for i, coseSig := range msg.coseMsg.Signatures {
		sig := Signature{
			coseSig:        &coseSig,
			SignatureBytes: coseSig.SignatureBytes,
		}
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
		// Parse the timestamps
		if _, ok := sig.coseSig.Headers.Unprotected[coseTimestampHeaderLabel]; !ok {
			return fmt.Errorf("no timestamps found in signature %d", i)
		}
		tsArray, ok := sig.coseSig.Headers.Unprotected[coseTimestampHeaderLabel].([]interface{})
		if !ok {
			return fmt.Errorf("in signature %d, failed to decode timestamps as an array", i)
		}
		for j, timestamp := range tsArray {
			tsBytes, ok := timestamp.([]byte)
			if !ok {
				return fmt.Errorf("in signature %d, failed to decode timestamp %d as a byte sequence", i, j)
			}
			// timestamp header found, parse them
			parsedTs, err := parseTimestamp(tsBytes)
			if err != nil {
				return fmt.Errorf("in signature %d, failed to parse timestamps %d: %w", i, j, err)
			}
			sig.Timestamps = append(sig.Timestamps, *parsedTs)
		}
		msg.Signatures = append(msg.Signatures, sig)
	}
	msg.isFinalized = true
	return
}

// Verify verifies each of the signatures stored in a SignMessage
// and makes sure the certificates chain to roots in the provided truststore.
//
// Signed timestamps in each signature are first verified, then certificates checked
// against a provided tsaPool. The SHA256 hash of the signature byte used as the
// timestamp payload.
//
// Signatures are then verified. Certificate expiration is checked based on the time
// of issuance of the last signed timestamp listed in the SignMessage.
// In practice, it means signatures are considered valid as long as
// certificates were valid at the time of issuance of the signature.
func (msg *SignMessage) Verify(tsaPool, localRoots *x509.CertPool) error {
	if !msg.isFinalized {
		return errors.New("message is not finalized, cannot verify signatures")
	}
	if msg.Payload == nil {
		return errors.New("message payload is not set, cannot verify signatures")
	}
	var verifiers = []cose.Verifier{}

	for i, sig := range msg.Signatures {
		var verificationTime time.Time
		// verify timestamps
		h256 := sha256.Sum256(sig.SignatureBytes)
		hasValidTimestamp := false
		for j, ts := range sig.Timestamps {
			err := verifyTimestamp(ts.Raw, h256[:], tsaPool)
			if err != nil {
				// if timestamp verification fails, log and continue
				fmt.Fprintf(os.Stderr, "warning: in signature %d, timestamp %d failed verification: %w", i, j, err)
				continue
			}
			verificationTime = ts.Time
			hasValidTimestamp = true
		}
		if !hasValidTimestamp {
			return fmt.Errorf("no trusted timestamp could be found")
		}
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
			for j := 1; j < len(sig.CertChain); j++ {
				opts.Intermediates.AddCert(sig.CertChain[j])
			}
		}
		// the first cert is the end-entity, start there to verify the chain
		_, err := sig.CertChain[0].Verify(opts)
		if err != nil {
			return fmt.Errorf("in signature %d, failed to verify certificate chain: %w", i, err)
		}
		// now that the chain is verified, add the signature to a cose verifier
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
