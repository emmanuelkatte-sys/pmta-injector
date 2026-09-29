// Package dkim signs and verifies email messages with DomainKeys Identified
// Mail (DKIM, RFC 6376).
//
// DKIM lets a domain take responsibility for a message by attaching a
// cryptographic signature over selected header fields and the body. A verifier
// fetches the signer's public key from DNS (at <selector>._domainkey.<domain>)
// and confirms the message was not altered in transit.
//
// Signing and verification both operate on the raw RFC 5322 message bytes —
// never on a parsed or reconstructed representation — so a signature is checked
// against exactly what was transmitted. Both "simple" and "relaxed" header and
// body canonicalization are supported; signing uses rsa-sha256, and
// verification additionally accepts the legacy rsa-sha1 algorithm. The package
// depends only on the Go standard library.
//
// # Signing
//
// Sign returns a DKIM-Signature field value over a raw message; the caller
// prepends the header field name and a trailing CRLF:
//
//	value, err := dkim.Sign(raw, dkim.SignOptions{
//		Domain:     "example.com",
//		Selector:   "default",
//		PrivateKey: key,
//	})
//	signed := append([]byte("DKIM-Signature: "+value+"\r\n"), raw...)
//
// GenerateKey, RecordName, RecordValue and RecordFragment produce a keypair and
// render the public half as the DNS TXT record verifiers look up.
//
// # Verifying
//
// Verify returns one VerifyResult per DKIM-Signature header, in header order. A
// nil resolver uses the system DNS resolver:
//
//	for _, r := range dkim.Verify(ctx, raw, nil) {
//		fmt.Println(r.Domain, r.Result)
//	}
//
// # Primitives
//
// The canonicalization and single-signature primitives (SplitMessage,
// CanonicalizeHeader, CanonicalizeBody, BuildSignedHeaders, VerifySignature,
// FetchKey, ParseTagList, RemoveBValue, StripWSP, HashBytes) are exported so
// that layered schemes such as ARC — whose ARC-Message-Signature is
// structurally a DKIM-Signature — can reuse the exact same code path.
package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// DefaultSelector is the selector RecordName and RecordFragment fall back to
// when none is given: "default", i.e. default._domainkey.<domain>.
const DefaultSelector = "default"

// GenerateKey creates an RSA DKIM keypair of the given size in bits and returns
// both halves PEM-encoded. The private PEM is the signing key (pass it to
// ParsePrivateKey); the public PEM feeds RecordValue to build the DNS record.
// Use at least 2048 bits for production keys.
func GenerateKey(bits int) (privatePEM, publicPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return privatePEM, publicPEM, nil
}

// RecordName returns the DKIM record name <selector>._domainkey.<domain>.
func RecordName(selector, domain string) string {
	if selector == "" {
		selector = DefaultSelector
	}
	return selector + "._domainkey." + domain
}

// RecordValue renders the DKIM DNS TXT value (v=DKIM1; k=rsa; p=<base64 DER>)
// from a PEM-encoded RSA public key (as produced by GenerateKey).
func RecordValue(publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		return "", fmt.Errorf("public key is not RSA")
	}
	// block.Bytes is the DER SubjectPublicKeyInfo — exactly what p= carries.
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(block.Bytes), nil
}

// RecordFragment renders a dnsmasq txt-record line for a DKIM record, splitting
// the value into <=255-char strings (the DNS TXT per-string limit) so that
// 2048-bit records — whose p= value exceeds 255 chars — stay valid:
//
//	txt-record=default._domainkey.d,"chunk1","chunk2"
func RecordFragment(name, value string) string {
	const maxLen = 255
	var chunks []string
	for i := 0; i < len(value); i += maxLen {
		end := i + maxLen
		if end > len(value) {
			end = len(value)
		}
		chunks = append(chunks, `"`+value[i:end]+`"`)
	}
	if len(chunks) == 0 {
		chunks = []string{`""`}
	}
	return "txt-record=" + name + "," + strings.Join(chunks, ",")
}
