package renard // import "go.mozilla.org/renard"

import (
	"bytes"
	"fmt"
	"io"
)

// FormatIdentifier identifies a supported input file format
type FormatIdentifier uint

// File formats are identified by a given constant
const (
	Zip FormatIdentifier = 1 + iota // import go.mozilla.org/renard/fileformat/zip
	Mar                             // import go.mozilla.org/renard/fileformat/mar
)

func (id FormatIdentifier) String() string {
	switch id {
	case Zip:
		return "zip"
	case Mar:
		return "mar"
	}
	return "unknown"
}

// Encoder implements file parsing, marshalling and unmarshalling
type Encoder interface {
	DecodeSignedSections() (r *bytes.Reader, err error)
	DecodeSignature() (coseSig []byte, err error)
	EncodeTo(w io.Writer, coseSig []byte) (err error)
}

// EncoderHandler provides an interface to make a new encoder
type EncoderHandler interface {
	NewEncoder(*bytes.Reader) (Encoder, error)
}

// AvailableEncoders contains the set of registered encoders
var AvailableEncoders = make(map[FormatIdentifier]EncoderHandler)

// RegisterEncoder a new encoder as available
func RegisterEncoder(id FormatIdentifier, h EncoderHandler) {
	if _, ok := AvailableEncoders[id]; ok {
		panic(fmt.Sprintf("Register: encoder %s has already been registered", id))
	}
	AvailableEncoders[id] = h
}
