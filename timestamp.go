package renard // go import "go.mozilla.org/renard"

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"go.mozilla.org/pkcs7"
)

// Timestamp represents a Signed Timestamp issued by a
// TimeStamp Authority (TSA) according to
// https://tools.ietf.org/html/rfc3161#section-2.4.1
type Timestamp struct {
	HashAlgorithm crypto.Hash
	HashedMessage []byte
	Time          time.Time
	Accuracy      time.Duration
	SerialNumber  *big.Int
	Certificates  []x509.Certificate

	// Extensions contains raw X.509 extensions from the Extensions field of the
	// timestamp. When parsing time-stamps, this can be used to extract
	// non-critical extensions that are not parsed by this package. When
	// marshaling time-stamps, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// timestamp response. Values override any extensions that would otherwise
	// be produced based on the other fields. The ExtraExtensions field is not
	// populated when parsing timestamp responses, see Extensions.
	ExtraExtensions []pkix.Extension

	// Raw contains the original pkcs7 encoded timestamp as returned by the TSA
	Raw []byte
}

// http://www.ietf.org/rfc/rfc3161.txt
// 2.4.1. Request Format
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"tag:0,optional"`
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// 2.4.2. Response Format
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue
}

type pkiStatusInfo struct {
	Status       int
	StatusString string `asn1:"optional"`
	FailInfo     int    `asn1:"optional"`
}

// requestTimestampFromTSA takes a TSA url and the bytes of a sha256 hash
// and returns a signed timestamp and an error.
func requestTimestampFromTSA(server string, h []byte, hAlg crypto.Hash) (*Timestamp, error) {
	// tsreq represents an timestamp request. See
	// https://tools.ietf.org/html/rfc3161#section-2.4.1
	tsreq, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				// the oid for the sha256 digest algorithm
				Algorithm: getOIDFromHashAlgorithm(hAlg),
				Parameters: asn1.RawValue{
					Tag: 5, /* ASN.1 NULL */
				},
			},
			HashedMessage: h,
		},
		CertReq:    true,
		Extensions: nil,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", server, bytes.NewReader(tsreq))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("tsa returned empty response")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa returned \"%d %s\" instead of 200 OK", resp.StatusCode, resp.Status)
	}
	// parse it to make sure we got a valid response
	var tsResp timeStampResp
	rest, err := asn1.Unmarshal(body, &tsResp)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in timestamp response")
	}

	if tsResp.Status.Status > 0 {
		return nil, fmt.Errorf("%s: %s", pkiFailureInfo(tsResp.Status.FailInfo).String(), tsResp.Status.StatusString)
	}

	if len(tsResp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("no pkcs7 data in timestamp response")
	}
	return parseAndVerifyTimestamp(tsResp.TimeStampToken.FullBytes)
}

// pkiFailureInfo contains the result of an timestamp request. See
// https://tools.ietf.org/html/rfc3161#section-2.4.2
type pkiFailureInfo int

const (
	// BadAlgorithm defines an unrecognized or unsupported Algorithm Identifier
	badAlgorithm pkiFailureInfo = 0
	// BadRequest indicates that the transaction not permitted or supported
	badRequest pkiFailureInfo = 2
	// BadDataFormat means tha data submitted has the wrong format
	badDataFormat pkiFailureInfo = 5
	// TimeNotAvailable indicates that TSA's time source is not available
	timeNotAvailable pkiFailureInfo = 14
	// UnacceptedPolicy indicates that the requested TSA policy is not supported
	// by the TSA
	unacceptedPolicy pkiFailureInfo = 15
	// UnacceptedExtension indicates that the requested extension is not supported
	// by the TSA
	unacceptedExtension pkiFailureInfo = 16
	// AddInfoNotAvailable means that the information requested could not be
	// understood or is not available
	addInfoNotAvailable pkiFailureInfo = 17
	// SystemFailure indicates that the request cannot be handled due to system
	// failure
	systemFailure pkiFailureInfo = 25
)

func (f pkiFailureInfo) String() string {
	switch f {
	case badAlgorithm:
		return "unrecognized or unsupported Algorithm Identifier"
	case badRequest:
		return "transaction not permitted or supported"
	case badDataFormat:
		return "the data submitted has the wrong format"
	case timeNotAvailable:
		return "the TSA's time source is not available"
	case unacceptedPolicy:
		return "the requested TSA policy is not supported by the TSA"
	case unacceptedExtension:
		return "the requested extension is not supported by the TSA"
	case addInfoNotAvailable:
		return "the additional information requested could not be understood or is not available"
	case systemFailure:
		return "the request cannot be handled due to system failure"
	default:
		return "unknown failure: " + strconv.Itoa(int(f))
	}
}

// parseAndVerifyTimestamp parses an timestamp in DER form. If the time-stamp contains a
// certificate then the signature over the response is checked.
//
// Invalid signatures or parse failures will result in a fmt.Errorf. Error
// responses will result in a ResponseError.
func parseAndVerifyTimestamp(rawTs []byte) (*Timestamp, error) {
	var inf tstInfo
	p7, err := pkcs7.Parse(rawTs)
	if err != nil {
		return nil, err
	}
	if len(p7.Certificates) > 0 {
		// Verify the signature of the timestamp and the chain of certificate
		// against the roots stored in the system truststore.
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		if err = p7.VerifyWithChain(systemCertPool); err != nil {
			return nil, err
		}
	}

	if _, err = asn1.Unmarshal(p7.Content, &inf); err != nil {
		return nil, err
	}
	if len(inf.MessageImprint.HashedMessage) == 0 {
		return nil, fmt.Errorf("timestamp response contains no hashed message")
	}
	ret := &Timestamp{
		HashedMessage: inf.MessageImprint.HashedMessage,
		SerialNumber:  inf.SerialNumber,
		Time:          inf.Time,
		Accuracy: time.Duration((time.Second * time.Duration(inf.Accuracy.Seconds)) +
			(time.Millisecond * time.Duration(inf.Accuracy.Milliseconds)) +
			(time.Microsecond * time.Duration(inf.Accuracy.Microseconds))),
		Extensions: inf.Extensions,
		Raw:        rawTs,
	}
	for _, c := range p7.Certificates {
		ret.Certificates = append(ret.Certificates, *c)
	}
	ret.HashAlgorithm = getHashAlgorithmFromOID(inf.MessageImprint.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

type tstInfo struct {
	Version        int
	Policy         asn1.RawValue
	MessageImprint messageImprint
	SerialNumber   *big.Int
	Time           time.Time
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

type accuracy struct {
	Seconds      int64 `asn1:"optional"`
	Milliseconds int64 `asn1:"tag:0,optional"`
	Microseconds int64 `asn1:"tag:1,optional"`
}

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

func getHashAlgorithmFromOID(target asn1.ObjectIdentifier) crypto.Hash {
	for hash, oid := range hashOIDs {
		if oid.Equal(target) {
			return hash
		}
	}
	return crypto.Hash(0)
}

func getOIDFromHashAlgorithm(target crypto.Hash) asn1.ObjectIdentifier {
	for hash, oid := range hashOIDs {
		if hash == target {
			return oid
		}
	}
	return nil
}
