package renard // import "go.mozilla.org/renard"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"

	"go.mozilla.org/cose"
)

const (
	// SigningBlockMagic is the magic string “Renard Scheme v1” (16 bytes)
	SigningBlockMagic = "Renard Scheme v1"

	// ZipSig is the zip signature “RNR1” in little-endian
	ZipSig = "\x4e\x52\x31\x52"
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

// CoseMultiSig is a COSE_Sign structure that follows
// the “Multiple Signers” format from RFC 8152 section C.1.3.
type CoseMultiSig struct {
	Headers    *cose.Headers
	Payload    []byte
	Signatures []cose.Signature
}

// SignMessage is the document that contains signatures and timestamps
// that protect a file. A user of the Renard scheme initializes a new
// SignMessage, populates it, then inserts it into a file according to
// its format. The raw representation of a SignMessage follows the
// COSE_Sign specification from rfc8152.
type SignMessage struct {
	Hashes           map[crypto.Hash][]byte // hashes of signable data indexed by hash algorithm
	Timestamps       []Timestamp            // array of rfc3161 timestamps
	Signatures       []Signature
	CounterSignature CounterSignature

	isHashed   bool
	fileFormat FileFormat
}

// A Signature is an authority-issued signature of the hash of the signed file
type Signature struct {
	Algorithm *cose.Algorithm
	CertChain []x509.Certificate
	Signature []byte
}

// CounterSignature is an optional signature that can be applied
// after the main signatures are issued to allow a 3rd party to add
// additional trust to a given artifact
type CounterSignature interface{}

// NewSignMessage constructs an empty SignMessage
func NewSignMessage() *SignMessage {
	msg := new(SignMessage)
	msg.Hashes = make(map[crypto.Hash][]byte)
	return msg
}

// SetFileFormatTo tells the marshaller to use a specific file format
// to insert and extract signature messages from files.
func (msg *SignMessage) SetFileFormatTo(ff FileFormat) {
	msg.fileFormat = ff
}

// TimestampFrom adds a rfc3161 signed timestamp retrieved an authority
// to a SignMessage.
//
// You can use any compliant public authority, such as
// http://timestamp.digicert.com or http://timestamp.comodoca.com/, as long
// as their roots are trusted by the system.
func (msg *SignMessage) TimestampFrom(server string) error {
	ts, err := RequestTimestampFromTSA(server, msg.Hashes[crypto.SHA256], crypto.SHA256)
	if err != nil {
		return err
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

// CalculateHashes takes a signable input and calculates various hashes
// that get stored in the message structure to later reuse them in signing
func (msg *SignMessage) CalculateHashes(input []byte) {
	h1 := sha1.Sum(input)
	msg.Hashes[crypto.SHA1] = h1[:]

	h256 := sha256.Sum256(input)
	msg.Hashes[crypto.SHA256] = h256[:]

	h384 := sha512.Sum384(input)
	msg.Hashes[crypto.SHA384] = h384[:]

	msg.isHashed = true
}

// Sign takes a private key and chain of certificates (ordered from end-entity to root)
// and uses the private key to sign the hash of an signable input previously computed.
// It then adds a Signature to the SignMessage with the computed signature and cert chain.
//
// The signing algorithm is determined by the key type. RSA keys get PS256, ECDSA
// keys get ES256 for P-256 and ES384 for P-384. No other curves are supported.
func (msg *SignMessage) Sign(signer crypto.Signer, chain []x509.Certificate) error {
	if !msg.isHashed {
		return errors.New("input hashes must be calculated prior to signing")
	}
	var (
		sig Signature
		err error
	)
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
	err = validateCertChain(chain)
	if err != nil {
		return err
	}
	sig.CertChain = chain

	sig.Signature, err = signer.Sign(rand.Reader, msg.Hashes[crypto.SHA256], nil)
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
