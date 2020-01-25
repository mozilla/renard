package zip // import "go.mozilla.org/renard/zip"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"go.mozilla.org/renard"
)

func init() {
	renard.RegisterEncoder(renard.Zip, new(handler))
}

type handler struct {
}

func (h *handler) NewEncoder(r *bytes.Reader) (renard.Encoder, error) {
	var err error
	e := &encoder{r: r}
	e.end, err = readDirectoryEnd(e.r, e.r.Size())
	if err != nil {
		return nil, err
	}
	if e.end.directoryRecords > uint64(e.r.Size())/fileHeaderLen {
		return nil, fmt.Errorf("zip: TOC declares impossible %d files in %d byte zip", e.end.directoryRecords, e.r.Size())
	}
	return e, nil
}

type encoder struct {
	r   *bytes.Reader
	end *directoryEnd
}

const (
	// SigningBlockMagic is the magic string “Renard Scheme v1” (16 bytes)
	SigningBlockMagic    = "Renard Scheme v1"
	signingBlockMagicLen = 16

	// ZipSig is the zip signature “RNR1”
	ZipSig    = "RNR1"
	zipSigLen = 4

	coseSigHeaderLen = 8
)

func (e *encoder) DecodeSignedSections() (*bytes.Reader, error) {
	var err error
	e.r.Seek(0, 0) // rewind the buffer
	// from the end directory, read 16 bytes that precedes to find
	// Renard's signing block magic string. If they match, we have a
	// signing block we need to exclude from the signable data.
	cursor := int64(e.end.directoryOffset) - signingBlockMagicLen
	magicBuf := make([]byte, signingBlockMagicLen)
	_, err = e.r.ReadAt(magicBuf, cursor)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if !bytes.Equal(magicBuf, []byte(SigningBlockMagic)) {
		// no signature block found, return the entire file as signable data
		e.r.Seek(0, 0) // rewind the buffer
		return e.r, nil
	}

	// Separate the signing block from the rest of the archive.
	// First read back 8 bytes to get the length of the cose signature,
	// then we jump back before the cose signature + 4 bytes to find the
	// the zip signature RNR1. If we find it, put the section that's before the
	// signing block, and the one after it, into a bytes.reader. fix the offset
	// to the beginning of central directory, since that changed when stripping
	// the signing block, and return that as signable data.
	coseSigLenBuf := make([]byte, coseSigHeaderLen)
	cursor -= coseSigHeaderLen
	_, err = e.r.ReadAt(coseSigLenBuf, cursor)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read cose signature length: %w", err)
	}
	var coseSigLen uint32
	rbuf := bytes.NewReader(coseSigLenBuf)
	err = binary.Read(rbuf, binary.LittleEndian, &coseSigLen)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cose signature length: %w", err)
	}

	// move the cursor back to the zip signature RNR1
	cursor -= (int64(coseSigLen) + zipSigLen)
	zipSigBuf := make([]byte, zipSigLen)
	_, err = e.r.ReadAt(zipSigBuf, cursor)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read zip signature: %w", err)
	}
	if !bytes.Equal(zipSigBuf, []byte(ZipSig)) {
		// no zip signature header found, malformed file, return an error
		return nil, fmt.Errorf("zip signature header RNR1 was not found in signing block, aborting parsing")
	}

	// now that cursor is set to the beginning of the signing block, copy
	// the beginning of the archive until the cursor
	signedSections := new(bytes.Buffer)
	e.r.Seek(0, 0) // rewind the buffer
	fileSectionLen, err := io.CopyN(signedSections, e.r, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to copy first part of signed section: %w", err)
	}
	if fileSectionLen != cursor {
		return nil, fmt.Errorf("failed to copy first part: %d bytes written when %d were expected",
			fileSectionLen, e.end.directoryOffset)
	}

	// jump over the signing block and copy the central directory
	coseSigningBlockLen := int64(zipSigLen + coseSigLen + coseSigHeaderLen + signingBlockMagicLen)
	e.r.Seek(fileSectionLen+coseSigningBlockLen, 0)
	centralDirLen, err := io.CopyN(signedSections, e.r, int64(e.end.directorySize))
	if err != nil {
		return nil, fmt.Errorf("failed to copy central directory of signed section: %w", err)
	}
	if centralDirLen != int64(e.end.directorySize) {
		return nil, fmt.Errorf("failed to copy central directory: %d bytes written when %d were expected",
			centralDirLen, e.end.directorySize)
	}

	// write the end directory with the updated offset to CD
	newEndCD := *e.end
	newEndCD.directoryOffset = uint64(fileSectionLen)
	err = writeEndCentralDir(signedSections, &newEndCD)
	if err != nil {
		return nil, fmt.Errorf("failed to write end of central directory: %w", err)
	}

	return bytes.NewReader(signedSections.Bytes()), nil
}

// EncodeTo encodes a file payload and its signature according to the ZIP specification
// of the Renard signing scheme.
// A signature block is created containing, in that order:
// - Zip signature
// - Cose signature bytes
// - Uint64(byte length of cose signature)
// - Magic ASCII string SigningBlockMagic
// The signature block is then inserted right before the start offset of the Central Directory
func (e *encoder) EncodeTo(w io.Writer, coseSig []byte) error {
	e.r.Seek(0, 0) // rewind the buffer
	// write everything until the start of the central directory
	fileSectionLen, err := io.CopyN(w, e.r, int64(e.end.directoryOffset))
	if err != nil {
		return fmt.Errorf("failed to encode output file: %w", err)
	}
	if fileSectionLen != int64(e.end.directoryOffset) {
		return fmt.Errorf("failed to encode output file: %d bytes written when %d were expected", fileSectionLen, e.end.directoryOffset)
	}

	// write the signing block
	err = binary.Write(w, binary.LittleEndian, []byte(ZipSig))
	if err != nil {
		return fmt.Errorf("failed to write signing block: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, []byte(coseSig))
	if err != nil {
		return fmt.Errorf("failed to write signing block: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint64(len(coseSig)))
	if err != nil {
		return fmt.Errorf("failed to write signing block: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, []byte(SigningBlockMagic))
	if err != nil {
		return fmt.Errorf("failed to write signing block: %w", err)
	}

	// write the central directory
	cdLen, err := io.CopyN(w, e.r, int64(e.end.directorySize))
	if err != nil {
		return fmt.Errorf("failed to encode output file: %w", err)
	}
	if cdLen != int64(e.end.directorySize) {
		return fmt.Errorf("failed to encode output file: %d bytes written when %d were expected", cdLen, e.end.directoryOffset)
	}

	// recalculate the offset from start of the archive to the start of
	// the central directory, so it points to right after the signing block
	newEndCD := *e.end
	newEndCD.directoryOffset = uint64(fileSectionLen) + zipSigLen + uint64(len(coseSig)) + coseSigHeaderLen + signingBlockMagicLen
	return writeEndCentralDir(w, &newEndCD)
}

func writeEndCentralDir(w io.Writer, end *directoryEnd) error {
	err := binary.Write(w, binary.LittleEndian, uint32(directoryEndSignature))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint16(0))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint16(0))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint16(end.dirRecordsThisDisk))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint16(end.directoryRecords))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint32(end.directorySize))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint32(end.directoryOffset))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	err = binary.Write(w, binary.LittleEndian, uint16(0))
	if err != nil {
		return fmt.Errorf("failed to write end directory: %w", err)
	}
	return nil
}

func (e *encoder) DecodeSignature() ([]byte, error) {
	e.r.Seek(0, 0) // rewind the buffer
	// read the 16 bytes that precedes the end directory offset.
	// If they magic Renard's signing block magic string, then we
	// have a signature block to return
	cursor := int64(e.end.directoryOffset) - signingBlockMagicLen
	magicBuf := make([]byte, signingBlockMagicLen)
	_, err := e.r.ReadAt(magicBuf, cursor)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if !bytes.Equal(magicBuf, []byte(SigningBlockMagic)) {
		// no signature block found
		return nil, fmt.Errorf("no signature block found in archive at offset %d", cursor)
	}
	// at this point, we have encountered a signature block, and we need to
	// separate it from the rest of the document to return the signable data.
	// First we read back 8 bytes to get the length of the cose signature,
	// then we verify that the 4 bytes that precede the cose signature match
	// the zip signature RNR1, and if so, we read the cose signature.
	coseSigLenBuf := make([]byte, coseSigHeaderLen)
	cursor -= coseSigHeaderLen
	_, err = e.r.ReadAt(coseSigLenBuf, cursor)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read cose signature length: %w", err)
	}
	var coseSigLen uint32
	rbuf := bytes.NewReader(coseSigLenBuf)
	err = binary.Read(rbuf, binary.LittleEndian, &coseSigLen)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cose signature length: %w", err)
	}
	// get the zip signature RNR1
	cursor -= (int64(coseSigLen) + zipSigLen)
	zipSigBuf := make([]byte, zipSigLen)
	_, err = e.r.ReadAt(zipSigBuf, cursor)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read zip signature: %w", err)
	}
	if !bytes.Equal(zipSigBuf, []byte(ZipSig)) {
		// no zip signature header found, malformed file, return an error
		return nil, fmt.Errorf("zip signature header RNR1 was not found in signing block, aborting parsing")
	}
	// get the cose signature
	cursor += zipSigLen
	coseSig := make([]byte, int(coseSigLen))
	_, err = e.r.ReadAt(coseSig, cursor)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read cose signature: %w", err)
	}
	return coseSig, nil
}
