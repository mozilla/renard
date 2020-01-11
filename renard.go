/*Package renard implements the RENARD signature scheme

Renard (RNR) is a signature scheme designed to provide strong integrity
guarantees on files. It is based on COSE and developed for Firefox add-ons
(web extensions) and updates.

The binary representation of an RNR signature is a COSE_Sign structure
stored in a signing block inserted in the ZIP or MAR envelope of a file,
immediately before the Central Directory section (similar to Android’s APKv2).
This method allows clients to verify signatures with minimal parsing of the
archive, while retaining a valid archive that can be decompressed using standard tools.

A signer receives an unsigned XPI archive, inserts needed metadata inside the
archive, then signs the SHA256 hash of the outer ZIP envelope using P-256.
The signature block is stored in a COSE document and inserted in the outer ZIP envelope.

A verifier receives a signed XPI archive, extracts the signature block from the ZIP,
calculates the SHA256 hash of the outer ZIP envelope (excluding the signature block)
and verifies the signature using the public key of the end-entity certificate stored
in the COSE document. The verifier then checks the certificate chain, signed timestamp,
and root against a local value.

*/
package renard // import "go.mozilla.org/renard"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"go.mozilla.org/cose"
)

const (
	// SigningBlockMagic is the magic string “Renard Scheme v1” (16 bytes)
	SigningBlockMagic = "Renard Scheme v1"

	// ZipSig is the zip signature “RNR1” in little-endian
	ZipSig = "\x4e\x52\x31\x52"

	coseTimestampHeaderLabel = 75
)

// FileFormat identifies a supported input file format
type FileFormat uint

// File formats are identified by a given constant
const (
	Zip FileFormat = 1 + iota // import go.mozilla.org/renard/fileformat/zip
	Mar                       // import go.mozilla.org/renard/fileformat/mar
)

// SigningBlock is the block containing a signature
// and its metadata that is inserted into a signed file
type SigningBlock struct {

	// The zip signature 0x4e523152 (“RNR1” in little-endian)
	ZipSig []byte

	// A marshalled COSE_Sign structure, of variable length
	Sig []byte

	// A uint64 representing the size in bytes of the COSE_Sign structure
	MultiSigByteSize uint64

	// The magic string “Renard Scheme v1” (16 bytes)
	Magic string
}

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

	coseMsg     *cose.SignMessage
	isFinalized bool
	fileFormat  FileFormat
	rand        io.Reader // rand is a CSPRNG from crypto/rand (default) or set to a specific reader (like an hsm)
}

// A Signature is an authority-issued signature of the hash of the signed file
type Signature struct {
	Algorithm          *cose.Algorithm
	CertChain          []x509.Certificate
	CoseSignatureBytes []byte
	coseSig            *cose.Signature
	signer             *cose.Signer
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

// SetFileFormat tells the marshaller to use a specific file format
// to insert and extract signature messages from files.
func (msg *SignMessage) SetFileFormat(ff FileFormat) {
	msg.fileFormat = ff
}

// SetRng configures the signers to use a different
// random number generator than the default from crypto/rand
func (msg *SignMessage) SetRng(rng io.Reader) {
	msg.rand = rng
}

// SetPayload sets the payload of the sign message. Later on, finalization will hash this
// payload alongside the protected headers and other metadata, then sign the results.
// The Payload is normally set to the signed sections of a file.
func (msg *SignMessage) SetPayload(payload []byte) {
	msg.Payload = payload
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

// ExtractSignedSections takes an input ZIP file and returns the sections
// that needs to be hashed for signing. For fresh zip files, input and output
// are identical. For ZIPs that already contain an AOS3 signing block, the
// extraction will remove the signing block, restore the offset of the zip
// central directory, and return the output.
func ExtractSignedSections(input []byte) (output []byte, err error) {
	// TODO: support already signed files
	return input, nil
}

// PrepareSignature takes a private key and chain of certificates (ordered from end-entity to root)
// and prepares a signature that will sign the message when finalized.
//
// The signing algorithm is determined by the key type. RSA keys get PS256, ECDSA
// keys get ES256 for P-256 and ES384 for P-384. No other curves are supported.
func (msg *SignMessage) PrepareSignature(signer crypto.Signer, chain []x509.Certificate) (err error) {
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
	// then store its DER version in the cose signature headers
	err = validateCertChain(chain)
	if err != nil {
		return err
	}
	var derChain [][]byte
	for _, cert := range chain {
		derChain = append(derChain, cert.Raw[:])
	}
	sig.coseSig.Headers.Protected["kid"] = derChain

	sig.signer, err = cose.NewSignerFromKey(sig.Algorithm, signer.(crypto.PrivateKey))
	if err != nil {
		return err
	}
	msg.Signatures = append(msg.Signatures, sig)
	return nil
}

func validateCertChain(chain []x509.Certificate) error {
	if len(chain) < 1 {
		return errors.New("invalid empty certificate chain")
	}
	if len(chain) == 1 {
		// no chain to verify when there's only one cert
		return nil
	}
	roots := x509.NewCertPool()
	inters := x509.NewCertPool()
	roots.AddCert(&chain[0])
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if len(chain) > 2 {
		// for chains greater than 2, add all intermediates to
		// the intermediate certpool in the verify options
		for i := 1; i < len(chain)-1; i++ {
			opts.Intermediates.AddCert(&chain[i])
		}
	}
	// now verify the end-entity
	_, err := chain[len(chain)-1].Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to verify end-entity chain to root: %w", err)
	}
	return nil
}

// Finalize signs a message with all the configured cose signers and makes
// it ready for marshalling and insertion into the destination file.
//
// A finalized message can no longer be modified, except for counter signatures.
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
	msg.isFinalized = true
	return nil
}

// Marshal encodes a finalized SignMessage into a COSE_Sign object
// compliant with https://tools.ietf.org/html/rfc8152#section-4.1
func (msg *SignMessage) Marshal() (coseSign []byte, err error) {
	// preconditions
	if !msg.isFinalized {
		return nil, errors.New("message must be finalized before marshalling")
	}
	return cose.Marshal(msg.coseMsg)
}

// Unmarshal parses a binary cose signature into a renard sign message.
func Unmarshal(coseMsg []byte) (msg *SignMessage, err error) {
	msg = NewSignMessage()
	parsedMsg, err := cose.Unmarshal(coseMsg)
	if err != nil {
		return msg, fmt.Errorf("failed to unmarshal cose message: %w", err)
	}
	cMsg := parsedMsg.(cose.SignMessage)
	msg.coseMsg = &cMsg

	// Parse the timestamps
	if timestamps, ok := msg.coseMsg.Headers.Protected[coseTimestampHeaderLabel]; ok {
		tsArray, ok := timestamps.([]interface{})
		if !ok {
			return msg, fmt.Errorf("failed to decode timestamps as an array")
		}
		for i, timestamp := range tsArray {
			tsBytes, ok := timestamp.([]byte)
			if !ok {
				return msg, fmt.Errorf("failed to decode %d timestamp as a byte sequence", i)
			}
			// timestamp header found, parse them
			parsedTs, err := parseAndVerifyTimestamp(tsBytes)
			if err != nil {
				return msg, fmt.Errorf("failed to parse timestamps: %w", err)
			}
			msg.Timestamps = append(msg.Timestamps, *parsedTs)
		}
	}
	return
}
