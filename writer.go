package renard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// ReadPayload extracts the signable data from a payload passed as a bytes.Reader
// in the format specified by the format identifier. The signable data is
// stored as a payload of the SignMessage that can be later timestamped
// and signed.
func (msg *SignMessage) ReadPayload(buf *bytes.Reader, ff FormatIdentifier) (err error) {
	if _, ok := AvailableEncoders[ff]; !ok {
		return fmt.Errorf("no parser is available for file format %s", ff)
	}
	msg.fileFormat = ff
	if msg.encoder == nil {
		msg.encoder, err = AvailableEncoders[msg.fileFormat].NewEncoder(buf)
		if err != nil {
			return
		}
	}
	msg.signableData, err = msg.encoder.DecodeSignedSections()
	if err != nil {
		return
	}
	// store the entire signable data reader into the payload
	// TODO: replace this with a reader instead of using memory
	msg.Payload = make([]byte, msg.signableData.Size())
	_, err = msg.signableData.ReadAt(msg.Payload, 0)
	if err != nil {
		return
	}
	return nil
}

// ReadSignature extracts and parses the signature data from a payload passed
// as a bytes.Reader in the format specified by the format identifier.
func (msg *SignMessage) ReadSignature(buf *bytes.Reader, ff FormatIdentifier) (err error) {
	if _, ok := AvailableEncoders[ff]; !ok {
		return fmt.Errorf("no parser is available for file format %s", ff)
	}
	msg.fileFormat = ff
	if msg.encoder == nil {
		msg.encoder, err = AvailableEncoders[msg.fileFormat].NewEncoder(buf)
		if err != nil {
			return fmt.Errorf("failed to make new encoder: %w", err)
		}
	}
	coseMsgBytes, err := msg.encoder.DecodeSignature()
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	return msg.ParseCoseSignMsg(coseMsgBytes)
}

// WritePayload constructs a file from the SignMessage and payload
// according to a format specified by the format identifier.
// The output file is passed to a writer, which is typically a file
// descriptor created with os.Open, or a bytes.Buffer.
func (msg *SignMessage) WritePayload(w io.Writer) error {
	if !msg.isFinalized {
		return errors.New("message must be finalized before writing")
	}
	if _, ok := AvailableEncoders[msg.fileFormat]; !ok {
		return fmt.Errorf("no parser is available for file format %s", msg.fileFormat)
	}
	msg.signableData.Seek(0, 0)
	return msg.encoder.EncodeTo(w, msg.coseMsgBytes)
}
