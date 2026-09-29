// Package arc verifies Authenticated Received Chain (ARC) headers per RFC 8617.
//
// ARC lets a message's authentication assessment survive intermediaries —
// mailing lists, forwarders, and other relays that legitimately modify a message
// and so break its original DKIM signature or SPF alignment. Each participating
// hop records what it saw by prepending an ARC set of three header fields:
//
//   - ARC-Authentication-Results (AAR): the authentication results the hop observed;
//   - ARC-Message-Signature (AMS): a DKIM-style signature over the message;
//   - ARC-Seal (AS): a signature over the chain of ARC header fields so far.
//
// A downstream receiver can then cryptographically confirm the whole chain and
// trust the earliest hop's assessment even though DKIM or SPF no longer pass
// directly. This package does both sides: Verify checks an existing chain, and
// Seal adds a new set as a forwarder — what Seal produces, Verify accepts.
//
// # Verifying
//
// Verify checks a raw RFC 5322 message and returns a chain-validation status
// together with a human-readable reason:
//
//	cv, reason := arc.Verify(ctx, raw, nil) // nil resolver → system DNS
//	fmt.Printf("arc=%s (%s)\n", cv, reason)
//
// It validates both the chain's structure — ARC sets numbered contiguously
// 1..N, each set complete — and its cryptography (RFC 8617 §5.2): the most
// recent ARC-Message-Signature must verify over the message, and every ARC-Seal
// must verify over the ARC header chain up to its instance. Signing keys are
// fetched from DNS at <selector>._domainkey.<domain>; pass a dkim.TXTResolver to
// override the lookup (for tests or a custom resolver), or nil for system DNS.
//
// # Sealing
//
// Seal is the counterpart to Verify: a forwarder adds one ARC set — an
// ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal for instance
// i=N — and returns the message with the set prepended, ready to relay. It
// records cv= by verifying the chain it is extending: "none" when there is no
// prior chain, otherwise the "pass"/"fail" Verify reports for the message as
// received.
//
//	res, err := arc.Seal(ctx, raw, arc.SealOptions{
//		Domain:      "example.com",
//		Selector:    "arc",
//		PrivateKey:  key, // *rsa.PrivateKey, e.g. from dkim.ParsePrivateKey
//		AuthResults: "example.com; spf=pass smtp.mailfrom=a@example.com",
//	})
//	// res.Message is raw with the new ARC set prepended; relay it.
//
// The ARC-Message-Signature is structurally a DKIM-Signature and the ARC-Seal a
// DKIM-style signature over the ARC header chain, both rsa-sha256, so sealing
// reuses the DKIM signing key and the same go-dkim canonicalization the verifier
// uses — what Seal produces, Verify (and any conformant RFC 8617 verifier)
// accepts over the exact transmitted bytes.
//
// # Status values
//
// The status is one of three RFC 8617 chain-validation values:
//
//   - "pass" — the chain is present and cryptographically intact;
//   - "fail" — the chain is present but broken: a bad signature, a tampered
//     field, or a structurally invalid chain;
//   - "none" — the message carries no ARC sets.
//
// Record it in a downstream Authentication-Results header as arc=<status>.
//
// # Building on go-dkim
//
// An ARC-Message-Signature is structurally a DKIM-Signature, and an ARC-Seal is
// a DKIM-style signature over the ARC header fields. This package therefore
// reuses the canonicalization and signature primitives exported by
// github.com/rest-mail/go-dkim — its only dependency — rather than
// reimplementing them, so ARC verification is byte-for-byte consistent with DKIM
// verification over the same message. ARC uses rsa-sha256: the ARC-Seal is
// verified with relaxed header canonicalization, and the ARC-Message-Signature
// is verified exactly as the DKIM-Signature it mirrors, honoring the
// canonicalization declared in its own c= tag — except that, per RFC 8617
// §4.1.2, the AMS is not versioned: any v= tag it carries is not part of it and
// is ignored rather than checked against the DKIM version rule.
package arc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rest-mail/go-dkim"
)

// arcSet is one ARC header set at a given instance: ARC-Authentication-Results,
// ARC-Message-Signature, ARC-Seal.
type arcSet struct {
	aar *dkim.Header
	ams *dkim.Header
	as  *dkim.Header
}

// Verify cryptographically verifies the ARC chain (RFC 8617 §5.2) in a raw
// message: the most recent ARC-Message-Signature must verify over the message
// (a DKIM-style signature), and every ARC-Seal must verify over the ARC header
// chain up to its instance. It returns a chain-validation status — "pass",
// "fail", or "none" — plus a human-readable reason. A nil resolver uses the
// system DNS resolver.
//
// Header/body canonicalization is shared with dkim.Verify (via the primitives
// exported by github.com/rest-mail/go-dkim), so ARC verification is consistent with
// DKIM verification and with any RFC 8617 verifier operating on the same bytes.
func Verify(ctx context.Context, rawMessage []byte, resolver dkim.TXTResolver) (string, string) {
	if resolver == nil {
		resolver = net.DefaultResolver.LookupTXT
	}
	headers, body := dkim.SplitMessage(rawMessage)

	sets, err := collectARCSets(headers)
	if err != nil {
		return "fail", err.Error()
	}
	if len(sets) == 0 {
		return "none", "no ARC sets present"
	}

	instances := make([]int, 0, len(sets))
	for i := range sets {
		instances = append(instances, i)
	}
	sort.Ints(instances)
	n := len(instances)

	// RFC 8617 §5.2 step 1 / §5.1.1: a message may carry at most 50 ARC sets. If
	// more exist, the chain-validation status is "fail" and the algorithm stops
	// here — before any structural or cryptographic checks. Enforcing the ceiling
	// first also bounds the work an inbound message can drive: each ARC-Seal is
	// verified by re-canonicalizing every prior set (O(n²)) with one DNS key
	// lookup per set, so an unbounded chain is a denial-of-service vector.
	if n > maxARCSets {
		return "fail", fmt.Sprintf("ARC chain has %d sets, exceeding the RFC 8617 maximum of %d", n, maxARCSets)
	}

	// Chain must be contiguous 1..N with every set complete.
	for pos, i := range instances {
		if i != pos+1 {
			return "fail", fmt.Sprintf("non-contiguous chain (expected i=%d, found i=%d)", pos+1, i)
		}
		if s := sets[i]; s.aar == nil || s.ams == nil || s.as == nil {
			return "fail", fmt.Sprintf("i=%d incomplete ARC set", i)
		}
	}

	// Each ARC-Seal's cv= (chain-validation) tag must be internally consistent
	// (RFC 8617 §5.2 steps 2 & 3C): "none" at i=1 and "pass" at every i>1. A
	// verifier must not trust an asserted cv=, but a self-inconsistent one is
	// conclusive on its own — a highest-instance cv=fail means a prior verifier
	// already declared the chain broken (§5.2 step 2), and cv=fail, a missing
	// tag, or any other value at any position describes a chain the RFC says can
	// never be continued (§5.1.3). Treat all of these as chain status "fail",
	// before the cryptographic checks, so an intact-but-laundered chain cannot
	// verify as "pass".
	for _, i := range instances {
		asTags := dkim.ParseTagList(sets[i].as.Value)

		// RFC 8617 §4.1.3: an ARC-Seal always covers the entire set of ARC header
		// fields, so — unlike the ARC-Message-Signature — it MUST NOT carry an h=
		// tag. A seal that includes one is malformed (even a bare "h="), and a
		// verifier MUST treat the chain as broken. Reject it here, before the
		// cryptographic checks, so a crafted h= (which arcSealBase does not honour)
		// cannot ride along on an otherwise-valid seal signature and launder the
		// chain to "pass".
		if _, ok := asTags["h"]; ok {
			return "fail", fmt.Sprintf("ARC-Seal (i=%d) carries a forbidden h= tag (RFC 8617 §4.1.3)", i)
		}

		cv := strings.ToLower(strings.TrimSpace(asTags["cv"]))
		want := "pass"
		if i == 1 {
			want = "none"
		}
		if cv != want {
			shown := cv
			if shown == "" {
				shown = "(absent)"
			}
			return "fail", fmt.Sprintf("ARC-Seal (i=%d) cv=%s, expected cv=%s", i, shown, want)
		}
	}

	// 1. The most recent ARC-Message-Signature must verify over the message.
	//
	// Verify only the DKIM crypto MECHANISM here, via the policy-free primitive:
	// an ARC-Message-Signature is structurally a DKIM-Signature but versionless by
	// design (RFC 8617 §4.1.2) and governed by ARC's rules, not RFC 6376 DKIM
	// policy. dkim.VerifySignature would PERMFAIL it on the missing v= tag (and
	// would additionally impose From-signed / i= alignment / t=/x= timing / key
	// t=s / s= flags that the AMS does not answer to). dkim.VerifySignatureBare
	// runs the same header-select + canonicalize + hash + RSA-verify against the
	// d=/s= key with NONE of that policy; a ResultPass means the AMS crypto is
	// valid. ARC's own policy — chain cv=, contiguous instance ordering, seal
	// h=-prohibited, seal s=/d= required — stays enforced above in this function.
	amsRes := dkim.VerifySignatureBare(ctx, *sets[n].ams, headers, body, resolver)
	if amsRes.Result != dkim.ResultPass {
		return "fail", fmt.Sprintf("ARC-Message-Signature (i=%d) %s: %s", n, amsRes.Result, amsRes.Reason)
	}

	// RFC 8617 §5.1.1: the ARC-Message-Signature MUST sign the From header. The
	// crypto check above uses dkim.VerifySignatureBare, which is policy-free by
	// design (RFC 8617 §4.1.2) and so — unlike dkim.VerifySignature — does NOT
	// impose DKIM's From-must-be-signed rule. Assert it here in the ARC layer,
	// against the AMS's already-parsed h= tag list: an AMS whose h= does not cover
	// From does not bind the author identity, so the message signature is invalid
	// and the chain is broken (cv=fail), even though the signature is otherwise
	// cryptographically valid. Parsing from the same collected AMS keeps this
	// byte-consistent with the field the crypto check and the seal chain saw.
	if !amsSignsFrom(dkim.ParseTagList(sets[n].ams.Value)["h"]) {
		return "fail", fmt.Sprintf("ARC-Message-Signature (i=%d) h= does not sign the From header (RFC 8617 §5.1.1)", n)
	}

	// 2. Every ARC-Seal must verify over the ARC header chain up to its instance.
	ordered := make([]*arcSet, 0, n)
	for _, i := range instances {
		ordered = append(ordered, sets[i])
	}
	for pos, i := range instances {
		if res, reason := verifyARCSeal(ctx, ordered[:pos+1], resolver); res != dkim.ResultPass {
			return "fail", fmt.Sprintf("ARC-Seal (i=%d) %s: %s", i, res, reason)
		}
	}

	return "pass", fmt.Sprintf("ARC chain cryptographically verified (%d set(s))", n)
}

// verifyARCSeal verifies the ARC-Seal of the LAST set in chain (ascending
// instance order) over the relaxed-canonicalized ARC header chain: for each set,
// ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal — with the final
// seal's b= emptied and no trailing CRLF (RFC 8617 §5.1.1).
func verifyARCSeal(ctx context.Context, chain []*arcSet, resolver dkim.TXTResolver) (string, string) {
	seal := chain[len(chain)-1].as
	tags := dkim.ParseTagList(seal.Value)
	if !strings.EqualFold(tags["a"], "rsa-sha256") {
		return dkim.ResultPermError, "unsupported ARC-Seal algorithm " + tags["a"]
	}

	// RFC 8617 §4.1.3: the ARC-Seal's s= (selector) and d= (domain) are REQUIRED
	// tags — together they name the public key at s=._domainkey.d= that verifies
	// the seal. A seal missing either is malformed and MUST NOT verify. This guard
	// is load-bearing, not defensive: dkim.FetchKey/dkim.RecordName substitute the
	// selector "default" for an empty s=, so a seal that simply omits s= would
	// otherwise resolve default._domainkey.<d> and verify against whatever key
	// happens to live there — a verification-integrity hole where an attacker drops
	// s= to pivot onto a selector that resolves. Reject the seal (chain status
	// "fail") here rather than fall back to a substituted selector. (The AMS path
	// is already safe: it verifies via dkim.VerifySignatureBare, which — like the
	// full primitive — requires s= among its mechanism tags.)
	if tags["s"] == "" {
		return dkim.ResultPermError, "ARC-Seal missing required s= (selector) tag"
	}
	if tags["d"] == "" {
		return dkim.ResultPermError, "ARC-Seal missing required d= (domain) tag"
	}

	base := arcSealBase(chain)

	sigBytes, err := base64.StdEncoding.DecodeString(dkim.StripWSP(tags["b"]))
	if err != nil {
		return dkim.ResultPermError, "invalid ARC-Seal b= base64"
	}
	// The seal is constrained to rsa-sha256 (checked above), so the key is fetched
	// with hashAlg "sha256". Deliberately IGNORE the returned KeyFlags for the
	// seal: t=s constrains an AUID i=, but an ARC-Seal's i= is the instance
	// number, and s= service-type is a DKIM email-signature rule RFC 8617 does not
	// direct the seal to reject on — honouring either would newly fail chains that
	// verified before.
	pub, _, kres := dkim.FetchKey(ctx, tags["s"], tags["d"], "sha256", resolver)
	if kres != "" {
		return kres, "ARC-Seal key lookup for " + dkim.RecordName(tags["s"], tags["d"])
	}
	hashed := dkim.HashBytes(crypto.SHA256, []byte(base))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, sigBytes); err != nil {
		return dkim.ResultFail, "ARC-Seal signature verification failed"
	}
	return dkim.ResultPass, "ok"
}

// arcSealBase builds the signing input for the ARC-Seal of the last set in the
// chain: relaxed-canonicalized AAR, AMS, AS for each set in ascending order,
// each followed by CRLF except the final seal (b= emptied, no trailing CRLF).
func arcSealBase(chain []*arcSet) string {
	var b strings.Builder
	last := len(chain) - 1
	for idx, s := range chain {
		b.WriteString(dkim.CanonicalizeHeader(*s.aar, "relaxed"))
		b.WriteString("\r\n")
		b.WriteString(dkim.CanonicalizeHeader(*s.ams, "relaxed"))
		b.WriteString("\r\n")
		if idx == last {
			stripped := *s.as
			stripped.Value = dkim.RemoveBValue(s.as.Value)
			stripped.Raw = dkim.RemoveBValue(s.as.Raw)
			b.WriteString(dkim.CanonicalizeHeader(stripped, "relaxed")) // no trailing CRLF
		} else {
			b.WriteString(dkim.CanonicalizeHeader(*s.as, "relaxed"))
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

// amsSignsFrom reports whether an ARC-Message-Signature h= tag list names the
// From header, as RFC 8617 §5.1.1 requires the AMS to do. The h= value is a
// colon-separated list of signed header field names; the match is on a whole
// entry (after trimming folding whitespace) and case-insensitive, so "from" or
// "From" counts but a different header whose name merely contains "from" (e.g.
// "x-from") does not. An empty or From-less h= returns false — the AMS does not
// cover the author identity and the chain must not verify.
func amsSignsFrom(hTag string) bool {
	for _, name := range strings.Split(hTag, ":") {
		if strings.EqualFold(strings.TrimSpace(name), "from") {
			return true
		}
	}
	return false
}

// collectARCSets parses a header block's ARC fields into per-instance sets,
// keyed by their i= tag. It enforces RFC 8617 §5.1.1 / §5.2 step 3A: a valid ARC
// set contains exactly one each of ARC-Authentication-Results,
// ARC-Message-Signature, and ARC-Seal. A second field of the same type at the
// same instance makes that set — and the whole chain — malformed, so
// collectARCSets returns an error naming the instance and field rather than
// letting a later copy overwrite an earlier one. Silently keeping "last wins"
// (or "first wins") is a parser-differential: two verifiers can select different
// copies and reach different verdicts over the same bytes. Callers treat the
// error as chain-validation "fail".
func collectARCSets(headers []dkim.Header) (map[int]*arcSet, error) {
	sets := map[int]*arcSet{}
	for idx := range headers {
		h := &headers[idx]
		name := strings.ToLower(h.Name)
		if name != "arc-authentication-results" &&
			name != "arc-message-signature" &&
			name != "arc-seal" {
			continue
		}
		// This IS an ARC header field. From here any structural defect fails the
		// whole collection — chain status "fail" for Verify, a malformed-chain error
		// for Seal — rather than being silently skipped: a field named ARC-* but
		// carrying a malformed i= means the message bears a BROKEN chain, not none.
		// The old strconv.Atoi path mapped i=0, i=-3, and an overflowing
		// i=99999999999999999999 all to 0 and dropped the set (i<1 == "not an ARC
		// header"), so a message that plainly carries ARC returned "none" instead of
		// "fail" (RFC 8617 §5.2).
		i, err := arcInstance(h.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", h.Name, err)
		}
		// RFC 6376 §3.2: a DKIM tag list with a repeated tag name is invalid. The
		// ARC-Message-Signature and ARC-Seal are DKIM tag lists, so a duplicate tag
		// in either fails the chain rather than silently taking dkim.ParseTagList's
		// last-wins value (a parser-differential another verifier may resolve to the
		// first). The ARC-Authentication-Results is Authentication-Results syntax,
		// not a DKIM tag list — its methods legally repeat (e.g. two dkim= results) —
		// so only its i= uniqueness, checked by arcInstance above, is enforced.
		if name != "arc-authentication-results" {
			if dup := firstDuplicateTag(h.Value); dup != "" {
				return nil, fmt.Errorf("%s (i=%d) has a duplicate %s= tag (RFC 6376 §3.2)", h.Name, i, dup)
			}
		}
		if sets[i] == nil {
			sets[i] = &arcSet{}
		}
		s := sets[i]
		switch name {
		case "arc-authentication-results":
			if s.aar != nil {
				return nil, fmt.Errorf("i=%d duplicate ARC-Authentication-Results", i)
			}
			s.aar = h
		case "arc-message-signature":
			if s.ams != nil {
				return nil, fmt.Errorf("i=%d duplicate ARC-Message-Signature", i)
			}
			// RFC 8617 §4.1.2: an ARC-Message-Signature has DKIM-Signature syntax
			// but the v= tag is not part of it. Strip any (unexpected) v= now, so
			// that both the AMS signature check and the ARC-Seal chain that covers
			// the AMS treat it as the versionless signature it is. See
			// stripAMSVersionTag.
			s.ams = stripAMSVersionTag(h)
		case "arc-seal":
			if s.as != nil {
				return nil, fmt.Errorf("i=%d duplicate ARC-Seal", i)
			}
			s.as = h
		}
	}
	return sets, nil
}

// maxInstance is the RFC 8617 §5.1.1 ceiling on an individual ARC set's instance
// number: i ranges over 1..50. It equals maxARCSets — a contiguous chain's highest
// instance is its set count — but names the per-set range constraint arcInstance
// enforces, distinct from the chain-length ceiling Verify checks.
const maxInstance = maxARCSets

// arcInstance extracts and validates the i= instance number of an ARC header
// value. A conformant instance is a bare decimal in 1..50 (RFC 8617 §4.1.1
// "instance = 1*2DIGIT", §5.1.1 range) appearing exactly once: no sign, no
// leading zero, no surrounding cruft, no overflow. It returns the parsed instance
// on success, or a non-nil error naming the defect — absent, duplicated,
// zero-padded, non-numeric, or out of range. collectARCSets turns that error into
// chain-validation "fail", so a field that IS an ARC header but carries a
// malformed i= is treated as a broken chain rather than silently skipped as if the
// message carried no ARC at all.
func arcInstance(value string) (int, error) {
	var raw string
	count := 0
	for _, kv := range tagPairs(value) {
		if strings.EqualFold(kv[0], "i") {
			count++
			raw = kv[1]
		}
	}
	switch {
	case count == 0:
		return 0, fmt.Errorf("missing required i= instance tag")
	case count > 1:
		return 0, fmt.Errorf("duplicate i= instance tag (RFC 6376 §3.2)")
	}
	if !validInstanceDigits(raw) {
		return 0, fmt.Errorf("malformed i= instance %q (want a 1..%d decimal with no sign or leading zero)", raw, maxInstance)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxInstance {
		return 0, fmt.Errorf("i= instance %q out of range 1..%d", raw, maxInstance)
	}
	return n, nil
}

// validInstanceDigits reports whether s is the canonical decimal form of an ARC
// instance: 1 or 2 ASCII digits with no leading zero (RFC 8617 §4.1.1
// "instance = 1*2DIGIT", canonical). It rejects "" , "007"/"01" (zero-padded or
// >2 digits), "0", "-3", "+1", "1 ", "1a", and any overflow, so only 1..99 in
// canonical form pass here; arcInstance additionally enforces the 1..50 range.
func validInstanceDigits(s string) bool {
	if len(s) < 1 || len(s) > 2 {
		return false
	}
	if s[0] < '1' || s[0] > '9' { // first digit non-zero: no leading zero, no sign
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// tagPairs splits a DKIM-style tag list ("k=v; k2=v2") into ordered (name, value)
// pairs, trimming FWS around each, WITHOUT the last-wins collapse
// dkim.ParseTagList performs. Preserving order and every occurrence lets callers
// enforce RFC 6376 §3.2 (a repeated tag name invalidates the list) and count a
// specific tag. Segments without '=' or with an empty name are skipped, matching
// ParseTagList.
func tagPairs(s string) [][2]string {
	var out [][2]string
	for _, seg := range strings.Split(s, ";") {
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(seg[:eq])
		if key == "" {
			continue
		}
		out = append(out, [2]string{key, strings.TrimSpace(seg[eq+1:])})
	}
	return out
}

// firstDuplicateTag returns the (lowercased) name of the first tag that appears
// more than once in a DKIM-style tag list, or "" if every tag name is unique.
// RFC 6376 §3.2: a tag list carrying a duplicate tag name is invalid.
func firstDuplicateTag(s string) string {
	seen := map[string]bool{}
	for _, kv := range tagPairs(s) {
		k := strings.ToLower(kv[0])
		if seen[k] {
			return k
		}
		seen[k] = true
	}
	return ""
}

// stripAMSVersionTag returns a copy of an ARC-Message-Signature header with any
// v= tag removed. RFC 8617 §4.1.2 defines the AMS with DKIM-Signature syntax but
// without a v= tag: unlike a DKIM-Signature, the AMS is not versioned. A
// conformant signer emits none, but an errant v= (e.g. v=DKIM1 copied from DKIM
// code, or added in transit) would otherwise trip the DKIM version rule
// (RFC 6376 §3.5, which rejects any v= not equal to 1) when the AMS is verified
// through go-dkim — failing the entire chain over a tag the RFC says is not part
// of the signature. Removing it here, at the single point Verify and Seal both
// collect ARC sets, makes an unexpected v= ignored rather than fatal, and keeps
// the AMS byte-identical to its versionless form for BOTH the AMS signature check
// AND the ARC-Seal that covers the AMS field. Every other byte is preserved, so a
// genuinely broken chain (bad body hash, tampered header, forged signature) still
// fails.
func stripAMSVersionTag(h *dkim.Header) *dkim.Header {
	out := *h
	out.Value = removeVTag(h.Value)
	out.Raw = removeVTag(h.Raw)
	return &out
}

// removeVTag deletes the entire v= tag — its name, value, and trailing
// delimiter — from a signature field, preserving every other byte. It differs
// from dkim.RemoveBValue, which blanks only a value while keeping the "b=" shell:
// the AMS must read as if no v= tag were ever present (RFC 8617 §4.1.2), so the
// whole tag is dropped. The v= tag is never the final tag of an AMS (b= is), so
// dropping its delimiter never leaves a dangling trailing ";".
func removeVTag(field string) string {
	var b strings.Builder
	i, n := 0, len(field)
	for i < n {
		seg := field[i:]
		hasDelim := false
		if j := strings.IndexByte(field[i:], ';'); j >= 0 {
			seg = field[i : i+j]
			i += j + 1
			hasDelim = true
		} else {
			i = n
		}
		if eq := strings.IndexByte(seg, '='); eq >= 0 && strings.EqualFold(strings.TrimSpace(seg[:eq]), "v") {
			continue // drop the whole v= tag together with its delimiter
		}
		b.WriteString(seg)
		if hasDelim {
			b.WriteByte(';')
		}
	}
	return b.String()
}
