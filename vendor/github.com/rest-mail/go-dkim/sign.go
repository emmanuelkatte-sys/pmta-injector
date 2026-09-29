package dkim

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// ParsePrivateKey parses a PEM-encoded RSA private key in PKCS#1 or PKCS#8 form.
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("dkim: invalid private key PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("dkim: parse private key: %w", err)
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("dkim: private key is not RSA")
	}
	return rk, nil
}

// SignOptions configures DKIM signing. Zero-value fields fall back to the
// documented defaults.
type SignOptions struct {
	Domain      string          // d= signing domain (required)
	Selector    string          // s= selector (required)
	PrivateKey  *rsa.PrivateKey // signing key (required)
	Headers     []string        // headers to sign; default from:to:subject:date:message-id
	HeaderCanon string          // "relaxed" (default) or "simple"
	BodyCanon   string          // "relaxed" (default) or "simple"
	Time        int64           // t= value; 0 omits the tag
}

var defaultSignedHeaders = []string{"from", "to", "subject", "date", "message-id"}

// Sign computes a DKIM-Signature header field VALUE (everything after
// "DKIM-Signature:") over the given raw RFC 5322 message. The caller prepends it
// as "DKIM-Signature: " + value + "\r\n".
//
// Signing operates on the message's ACTUAL header/body bytes and shares its
// canonicalization with Verify (via BuildSignedHeaders and CanonicalizeBody), so
// a message signed here verifies here — and, because it signs the real
// transmitted bytes rather than a reconstruction, at any RFC 6376 verifier. Only
// headers that are actually present are included in h=.
func Sign(rawMessage []byte, opt SignOptions) (string, error) {
	if opt.Domain == "" || opt.Selector == "" || opt.PrivateKey == nil {
		return "", fmt.Errorf("dkim.Sign: domain, selector and private key are required")
	}
	headerCanon := opt.HeaderCanon
	if headerCanon == "" {
		headerCanon = "relaxed"
	}
	bodyCanon := opt.BodyCanon
	if bodyCanon == "" {
		bodyCanon = "relaxed"
	}
	wantHeaders := opt.Headers
	if len(wantHeaders) == 0 {
		wantHeaders = defaultSignedHeaders
	}

	// RFC 6376 §5.4: the From header field MUST be signed. Refuse a caller header
	// list that omits it rather than emit a signature no conforming verifier will
	// accept. The check is case-insensitive and space-tolerant, matching how the
	// names are normalized below.
	requestsFrom := false
	for _, name := range wantHeaders {
		if strings.EqualFold(strings.TrimSpace(name), "from") {
			requestsFrom = true
			break
		}
	}
	if !requestsFrom {
		return "", fmt.Errorf("dkim.Sign: the From header must be signed (RFC 6376 §5.4); include \"from\" in SignOptions.Headers")
	}

	allHeaders, body := SplitMessage(rawMessage)

	// Only sign headers that exist, preserving the requested order.
	present := map[string]bool{}
	for _, h := range allHeaders {
		present[strings.ToLower(h.Name)] = true
	}
	var signed []string
	for _, name := range wantHeaders {
		if present[strings.ToLower(strings.TrimSpace(name))] {
			signed = append(signed, strings.ToLower(strings.TrimSpace(name)))
		}
	}

	// From was requested, but the present-filter drops any header the message
	// lacks. If the message itself carries no From header, the h= list still
	// wouldn't cover From — again invalid under RFC 6376 §5.4, so refuse.
	signedFrom := false
	for _, name := range signed {
		if name == "from" {
			signedFrom = true
			break
		}
	}
	if !signedFrom {
		return "", fmt.Errorf("dkim.Sign: message has no From header to sign (RFC 6376 §5.4)")
	}

	hTag := strings.Join(signed, ":")

	// Body hash.
	bodyHash := HashBytes(crypto.SHA256, []byte(CanonicalizeBody(body, bodyCanon)))
	bh := base64.StdEncoding.EncodeToString(bodyHash)

	// DKIM-Signature value with an empty b=.
	var sb strings.Builder
	sb.WriteString("v=1; a=rsa-sha256; c=" + headerCanon + "/" + bodyCanon)
	sb.WriteString("; d=" + opt.Domain + "; s=" + opt.Selector)
	if opt.Time > 0 {
		fmt.Fprintf(&sb, "; t=%d", opt.Time)
	}
	sb.WriteString("; h=" + hTag + "; bh=" + bh + "; b=")
	valueNoB := sb.String()

	// Build the signed data exactly as Verify does: the signed headers, then the
	// DKIM-Signature header itself (b= empty, no trailing CRLF). Reusing
	// BuildSignedHeaders is what guarantees sign/verify canonicalization parity.
	sigHeader := Header{Name: "DKIM-Signature", Value: " " + valueNoB, Raw: "DKIM-Signature: " + valueNoB}
	signedData := BuildSignedHeaders(hTag, allHeaders, sigHeader, headerCanon)

	hashed := HashBytes(crypto.SHA256, []byte(signedData))
	sig, err := rsa.SignPKCS1v15(rand.Reader, opt.PrivateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("dkim.Sign: %w", err)
	}
	return valueNoB + base64.StdEncoding.EncodeToString(sig), nil
}
