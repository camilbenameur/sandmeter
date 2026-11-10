package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// PayloadType is the DSSE payloadType of a receipt.
const PayloadType = "application/vnd.ringfence.receipt+json"

// Envelope is a DSSE envelope (github.com/secure-systems-lab/dsse).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // std base64
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // std base64
}

// pae is the DSSE pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths in decimal ASCII.
func pae(payloadType string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteByte(' ')
	b.Write(body)
	return b.Bytes()
}

// KeyID is the first 16 hex characters of sha256 of the public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])[:16]
}

// Sign returns the DSSE envelope JSON for r, signed with key. The signature
// covers the canonical receipt bytes only; see the package comment for what
// that does and does not prove.
func Sign(r Receipt, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("sign receipt: invalid private key")
	}
	body, err := Canonical(r)
	if err != nil {
		return nil, fmt.Errorf("canonicalize receipt: %w", err)
	}
	sig := ed25519.Sign(key, pae(PayloadType, body))
	env := Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(body),
		Signatures: []Signature{{
			KeyID: KeyID(key.Public().(ed25519.PublicKey)),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	return out, nil
}

// Verify checks an envelope against pub and returns the decoded receipt.
// It checks the payload type, finds the signature with the matching key id,
// verifies it over the PAE, then decodes the payload strictly (unknown fields
// are errors) and checks the schema.
func Verify(envelope []byte, pub ed25519.PublicKey) (Receipt, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Receipt{}, errors.New("verify receipt: invalid public key")
	}
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return Receipt{}, fmt.Errorf("decode envelope: %w", err)
	}
	if env.PayloadType != PayloadType {
		return Receipt{}, fmt.Errorf("unexpected payload type %q", env.PayloadType)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Receipt{}, fmt.Errorf("decode payload: %w", err)
	}
	if err := checkSignature(env, pub, body); err != nil {
		return Receipt{}, err
	}
	return decodeStrict(body)
}

func checkSignature(env Envelope, pub ed25519.PublicKey, body []byte) error {
	id := KeyID(pub)
	for _, s := range env.Signatures {
		if s.KeyID != id {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return fmt.Errorf("decode signature: %w", err)
		}
		if !ed25519.Verify(pub, pae(env.PayloadType, body), sig) {
			return errors.New("signature does not match payload")
		}
		return nil
	}
	return fmt.Errorf("no signature for key id %s", id)
}

func decodeStrict(body []byte) (Receipt, error) {
	var r Receipt
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Receipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Receipt{}, errors.New("decode receipt: trailing data")
	}
	if r.Schema != SchemaV1 {
		return Receipt{}, fmt.Errorf("unsupported schema %q", r.Schema)
	}
	return r, nil
}
