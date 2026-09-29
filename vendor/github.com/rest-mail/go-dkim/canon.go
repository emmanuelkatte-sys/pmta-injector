package dkim

import (
	"bytes"
	"crypto"
	"crypto/sha1" //nolint:gosec // rsa-sha1 is a legacy DKIM algorithm receivers must still verify
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SplitMessage normalizes line endings to CRLF and splits a raw RFC 5322
// message into ordered header fields and the body. Line-ending normalization
// (bare LF / lone CR → CRLF) reconstructs the canonical wire form the signer
// hashed, in case an intermediate stored the message with LF-only endings.
//
// It is exported so that layered signature schemes (e.g. ARC) can parse a raw
// message into the same Header slice / body that Sign and Verify operate on.
func SplitMessage(raw []byte) ([]Header, string) {
	s := string(raw)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")

	var headerBlock string
	body := ""
	if idx := strings.Index(s, "\r\n\r\n"); idx >= 0 {
		headerBlock = s[:idx]
		body = s[idx+4:]
	} else {
		headerBlock = strings.TrimSuffix(s, "\r\n")
	}
	return parseHeaders(headerBlock), body
}

// parseHeaders splits a header block (fields joined by CRLF, no trailing CRLF)
// into ordered header fields, folding continuation lines back into their field.
func parseHeaders(block string) []Header {
	if block == "" {
		return nil
	}
	var headers []Header
	for _, line := range strings.Split(block, "\r\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Continuation of the previous field.
			if len(headers) == 0 {
				continue
			}
			last := &headers[len(headers)-1]
			last.Raw += "\r\n" + line
			last.Value += "\r\n" + line
			continue
		}
		eq := strings.IndexByte(line, ':')
		if eq < 0 {
			continue // not a valid header field
		}
		headers = append(headers, Header{
			Name:  strings.TrimSpace(line[:eq]),
			Value: line[eq+1:],
			Raw:   line,
		})
	}
	return headers
}

// CanonicalizeHeader canonicalizes a single header field per RFC 6376 §3.4,
// using either "relaxed" or "simple" canonicalization. The returned string has
// NO trailing CRLF — the caller appends one between signed headers (and none
// after the trailing signature header being verified).
func CanonicalizeHeader(h Header, canon string) string {
	if canon == "relaxed" {
		return strings.ToLower(strings.TrimSpace(h.Name)) + ":" + relaxHeaderValue(h.Value)
	}
	// simple: the field exactly as it appeared.
	return h.Raw
}

// relaxHeaderValue applies relaxed value canonicalization: unfold, collapse WSP
// runs to a single SP, and drop leading (post-colon) and trailing WSP.
func relaxHeaderValue(v string) string {
	v = strings.ReplaceAll(v, "\r\n", "") // unfold
	var b strings.Builder
	inWSP := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '\t' {
			inWSP = true
			continue
		}
		if inWSP {
			if b.Len() > 0 { // suppress leading WSP
				b.WriteByte(' ')
			}
			inWSP = false
		}
		b.WriteByte(c)
	}
	return b.String() // trailing WSP naturally dropped (never flushed)
}

// CanonicalizeBody applies simple or relaxed body canonicalization (RFC 6376
// §3.4.3 / §3.4.4). Input is a CRLF-normalized body (as returned by
// SplitMessage). The result always ends in exactly one CRLF, except that a
// relaxed canonicalization of an empty body is the empty string.
func CanonicalizeBody(body, canon string) string {
	if canon == "relaxed" {
		if body == "" {
			return ""
		}
		lines := strings.Split(body, "\r\n")
		for i, ln := range lines {
			lines[i] = relaxBodyLine(ln)
		}
		for len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if len(lines) == 0 {
			return ""
		}
		return strings.Join(lines, "\r\n") + "\r\n"
	}
	// simple: strip trailing empty lines, guarantee exactly one trailing CRLF.
	for strings.HasSuffix(body, "\r\n") {
		body = body[:len(body)-2]
	}
	return body + "\r\n"
}

// relaxBodyLine collapses WSP runs within a body line to a single SP (a leading
// run collapses to a single leading SP — it is NOT removed) and strips trailing
// WSP.
func relaxBodyLine(line string) string {
	var b strings.Builder
	inWSP := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == ' ' || c == '\t' {
			inWSP = true
			continue
		}
		if inWSP {
			b.WriteByte(' ') // leading SP preserved for body (unlike headers)
			inWSP = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ParseTagList parses a DKIM tag=value list ("k=v; k2=v2") into a map. Keys and
// the ends of values are trimmed; internal FWS in values is preserved (callers
// strip it via StripWSP where it is insignificant, e.g. b=, bh=, p=). It parses
// DKIM-Signature, DKIM key records, and ARC header (i=, cv=, …) tag lists alike.
func ParseTagList(s string) map[string]string {
	out := map[string]string{}
	for _, seg := range strings.Split(s, ";") {
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(seg[:eq])
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(seg[eq+1:])
	}
	return out
}

// ParseTagListStrict parses a DKIM tag=value list like ParseTagList but enforces
// the RFC 6376 §3.2 well-formedness rules the verification paths require:
//
//   - "Tags with duplicate names MUST NOT occur within a single tag-list; if a
//     tag name does occur more than once, the entire tag-list is invalid."
//     Silently taking one of the values (as a last-wins parse does) lets two
//     verifiers reach different verdicts about the same message, so a repeated
//     tag name is an error.
//   - A non-empty segment that lacks "=" is a malformed tag-spec and is an
//     error (§6.1.1 cautions against being liberal in what is accepted). An
//     empty segment — e.g. from the optional trailing ";" the ABNF allows, or
//     surrounding folding whitespace — is ignored, not rejected.
//   - A segment with an empty tag name ("=value") is malformed
//     (tag-name = ALPHA *ALNUMPUNC) and is an error.
//
// On any violation it returns a nil map and an error, so a caller verifying a
// DKIM-Signature or a DNS key record can PERMFAIL (or skip the record) rather
// than resolve a malformed list to an arbitrary value.
func ParseTagListStrict(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, seg := range strings.Split(s, ";") {
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			if strings.TrimSpace(seg) == "" {
				continue // empty segment: trailing ";" or surrounding FWS
			}
			return nil, fmt.Errorf("malformed tag-list segment %q (missing '=')", strings.TrimSpace(seg))
		}
		key := strings.TrimSpace(seg[:eq])
		if key == "" {
			return nil, fmt.Errorf("malformed tag-list segment (empty tag name)")
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate tag %q in tag-list", key)
		}
		out[key] = strings.TrimSpace(seg[eq+1:])
	}
	return out, nil
}

// RemoveBValue blanks the value of the b= tag in a signature field (a
// DKIM-Signature, ARC-Message-Signature, or ARC-Seal value) while preserving
// every other byte (including the "b=" itself), as required before
// canonicalizing the signature header for verification.
func RemoveBValue(field string) string {
	var b strings.Builder
	i, n := 0, len(field)
	for i < n {
		j := strings.IndexByte(field[i:], ';')
		var seg string
		hasDelim := false
		if j < 0 {
			seg = field[i:]
			i = n
		} else {
			seg = field[i : i+j]
			i = i + j + 1
			hasDelim = true
		}
		if eq := strings.IndexByte(seg, '='); eq >= 0 && strings.EqualFold(strings.TrimSpace(seg[:eq]), "b") {
			b.WriteString(seg[:eq+1]) // keep "b=", drop the value
		} else {
			b.WriteString(seg)
		}
		if hasDelim {
			b.WriteByte(';')
		}
	}
	return b.String()
}

// StripWSP removes all whitespace (SP, TAB, CR, LF) — used on base64 tag values
// (b=, bh=, p=) that may be folded across lines.
func StripWSP(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// HashBytes hashes data with the given hash (crypto.SHA256 or crypto.SHA1, the
// two algorithms RFC 6376 defines) and returns the digest.
func HashBytes(h crypto.Hash, data []byte) []byte {
	if h == crypto.SHA1 {
		sum := sha1.Sum(data) //nolint:gosec // legacy DKIM algorithm
		return sum[:]
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }

// parseUint parses a DKIM tag value that RFC 6376 defines as digits only (e.g.
// the l= body-length tag, sig-l-tag = ... 1*76DIGIT — §3.5). It rejects any
// value that is not composed solely of ASCII digits, including a leading "+" or
// "-" sign. This matters: strconv.Atoi accepts a sign, so without this guard a
// negative l= would parse cleanly and then slice the body with a negative bound
// (canonBody[:-1]), panicking — a remotely triggerable crash since the
// signature header is attacker-controlled. strconv.Atoi still rejects values
// that overflow int.
func parseUint(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.Atoi(s)
}

// parseTimeTag parses a DKIM timestamp tag (t= or x=), whose RFC 6376 §3.5 ABNF
// is 1*12DIGIT — an unsigned decimal count of seconds since the Unix epoch. It
// rejects an empty value, any non-digit (including a leading "+" or "-" sign),
// and a value longer than 12 digits, so a syntactically invalid expiration is a
// clean error rather than being silently ignored. The result is returned as
// int64 so the epoch-second comparison against the current time is correct on a
// 32-bit platform (where int would overflow beyond year 2038).
func parseTimeTag(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 12 {
		return 0, strconv.ErrSyntax
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func asDNSError(err error, target **net.DNSError) bool { return errors.As(err, target) }
