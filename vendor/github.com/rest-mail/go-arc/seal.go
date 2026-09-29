package arc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/rest-mail/go-dkim"
)

// maxARCSets is the RFC 8617 §5.1.1 ceiling on ARC chain length: a message must
// carry no more than 50 ARC sets. Seal refuses to add the 51st.
const maxARCSets = 50

// defaultAMSHeaders are the message headers an ARC-Message-Signature covers when
// SealOptions.Headers is empty — the same default set go-dkim signs.
var defaultAMSHeaders = []string{"from", "to", "subject", "date", "message-id"}

// SealOptions configures Seal. Domain, Selector, and PrivateKey are required;
// every other field falls back to a documented default.
type SealOptions struct {
	// Domain is the d= signing domain for the ARC-Message-Signature and
	// ARC-Seal (required).
	Domain string
	// Selector is the s= selector; its key record lives at
	// <Selector>._domainkey.<Domain> (required).
	Selector string
	// PrivateKey is the RSA key that signs the ARC set (required). Parse a PEM
	// key with dkim.ParsePrivateKey.
	PrivateKey *rsa.PrivateKey
	// AuthResults is the authentication-results content recorded in the
	// ARC-Authentication-Results field, after the "i=N; " instance prefix that
	// Seal adds — e.g. "example.com; spf=pass smtp.mailfrom=a@example.com;
	// dkim=pass header.d=example.com". If empty, "<Domain>; none" is recorded.
	AuthResults string
	// Headers lists the message headers the ARC-Message-Signature covers (its h=
	// tag). Empty means from:to:subject:date:message-id. Only headers actually
	// present in the message are signed, matching dkim.Sign.
	Headers []string
	// HeaderCanon is the ARC-Message-Signature header canonicalization,
	// "relaxed" (default) or "simple". The ARC-Seal is always relaxed per
	// RFC 8617.
	HeaderCanon string
	// BodyCanon is the ARC-Message-Signature body canonicalization, "relaxed"
	// (default) or "simple".
	BodyCanon string
	// Time is the t= timestamp stamped into both the ARC-Message-Signature and
	// the ARC-Seal. Zero means "now" (time.Now().Unix()); set it explicitly for
	// reproducible output.
	Time int64
	// Resolver fetches the DNS TXT keys used to validate the existing ARC chain
	// when computing cv= (see Seal). It matches net.Resolver.LookupTXT; nil uses
	// the system resolver. It is only consulted when the message already carries
	// an ARC chain (i.e. this is not instance 1).
	Resolver dkim.TXTResolver
}

// SealResult is the ARC set Seal produced for instance i=N.
type SealResult struct {
	// Instance is the ARC instance number (i=) of the new set: 1 more than the
	// highest instance already on the message (RFC 8617 §5.1 step 3).
	Instance int
	// ChainValidation is the cv= value recorded in the ARC-Seal — "none" (no
	// prior chain), "pass", or "fail" (RFC 8617 §5.1.1).
	ChainValidation string
	// AAR, AMS, and AS are the three new header fields, each a complete RFC 5322
	// field ("Name: value") with no trailing CRLF: ARC-Authentication-Results,
	// ARC-Message-Signature, and ARC-Seal respectively.
	AAR string
	AMS string
	AS  string
	// Message is rawMessage with the new ARC set prepended in RFC 8617 order
	// (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results, then the
	// original message), ready to relay.
	Message []byte
}

// Seal adds one ARC set (RFC 8617 §5.1) to a raw RFC 5322 message and returns
// it, sealing the message for the next hop. It is the counterpart to Verify:
// what Seal produces, Verify accepts.
//
// For instance i=N (one past the highest instance already on the message, per
// RFC 8617 §5.1 step 3) it builds the three ARC header fields:
//
//   - ARC-Authentication-Results (AAR): "i=N; " + opt.AuthResults;
//   - ARC-Message-Signature (AMS): a DKIM-style rsa-sha256 signature over the
//     message headers and body, structurally a DKIM-Signature but tagged with
//     i= and carrying no v=;
//   - ARC-Seal (AS): an rsa-sha256 signature over the relaxed-canonicalized ARC
//     header chain up to and including this set, carrying cv=.
//
// cv= is the chain-validation status of the chain being extended, computed by
// verifying it: "none" if the message carries no prior ARC sets, otherwise the
// "pass"/"fail" that Verify returns for the message as received. Computing cv
// for i>1 fetches the prior signers' keys via opt.Resolver (nil → system DNS);
// i=1 needs no lookup.
//
// The AMS and AS share go-dkim's canonicalization and signing primitives (and
// the very ARC-Seal base builder Verify uses), so a freshly sealed message
// verifies here — and at any conformant RFC 8617 verifier — over the exact
// transmitted bytes.
func Seal(ctx context.Context, rawMessage []byte, opt SealOptions) (*SealResult, error) {
	if opt.Domain == "" || opt.Selector == "" || opt.PrivateKey == nil {
		return nil, fmt.Errorf("arc.Seal: domain, selector and private key are required")
	}
	// Reject caller-supplied strings carrying a bare CR or LF before they are
	// interpolated into header field values. Seal writes Domain and Selector into
	// the d=/s= tags and AuthResults into the ARC-Authentication-Results content
	// with fmt.Sprintf; a CRLF in any of them would fold in additional header
	// fields — a header injection turning one sealed field into several. RFC 5322
	// header field values contain no bare CR or LF, so refuse them here rather than
	// emit a malformed, attacker-shaped message.
	if err := rejectHeaderInjection(opt); err != nil {
		return nil, err
	}
	headerCanon := opt.HeaderCanon
	if headerCanon == "" {
		headerCanon = "relaxed"
	}
	bodyCanon := opt.BodyCanon
	if bodyCanon == "" {
		bodyCanon = "relaxed"
	}
	if headerCanon != "relaxed" && headerCanon != "simple" {
		return nil, fmt.Errorf("arc.Seal: unsupported header canonicalization %q", headerCanon)
	}
	if bodyCanon != "relaxed" && bodyCanon != "simple" {
		return nil, fmt.Errorf("arc.Seal: unsupported body canonicalization %q", bodyCanon)
	}
	signTime := opt.Time
	if signTime == 0 {
		signTime = time.Now().Unix()
	}

	headers, body := dkim.SplitMessage(rawMessage)
	prior, highest, err := priorChain(headers)
	if err != nil {
		return nil, fmt.Errorf("arc.Seal: incoming ARC chain malformed: %w", err)
	}
	// RFC 8617 §5.1 step 3: the new ARC set's instance number is 1 more than the
	// HIGHEST instance already on the message — not the count of prior sets. On a
	// well-formed contiguous chain the two are equal, but a gapped chain (say i=1
	// and i=3, a 2-set chain) makes count-based derivation emit i=3, colliding with
	// the existing i=3 and producing a self-invalidating message with two ARC-Seals
	// at the same instance (issue #12). Deriving from the highest instance never
	// collides. (A gapped chain is non-contiguous, so Verify reports cv=fail and the
	// new seal is scoped to this set alone — but the instance must be right first.)
	instance := highest + 1
	if instance > maxARCSets {
		return nil, fmt.Errorf("arc.Seal: highest ARC instance is i=%d; a new set would exceed the RFC 8617 maximum of %d", highest, maxARCSets)
	}

	// cv= records the validation status of the chain we are extending
	// (RFC 8617 §5.1.1): none with no prior chain, else pass/fail from verifying
	// the message exactly as Verify does.
	cv, _ := Verify(ctx, rawMessage, opt.Resolver)

	// 1. ARC-Authentication-Results.
	authResults := opt.AuthResults
	if authResults == "" {
		authResults = opt.Domain + "; none"
	}
	aar := field("ARC-Authentication-Results", fmt.Sprintf("i=%d; %s", instance, authResults))

	// 2. ARC-Message-Signature: a DKIM-style signature over the message.
	hTag := amsHeaderTag(headers, opt.Headers)
	bh := base64.StdEncoding.EncodeToString(
		dkim.HashBytes(crypto.SHA256, []byte(dkim.CanonicalizeBody(body, bodyCanon))))
	amsNoB := fmt.Sprintf("i=%d; a=rsa-sha256; c=%s/%s; d=%s; s=%s; t=%d; h=%s; bh=%s; b=",
		instance, headerCanon, bodyCanon, opt.Domain, opt.Selector, signTime, hTag, bh)
	amsSig, err := signRSA(opt.PrivateKey,
		dkim.BuildSignedHeaders(hTag, headers, *field("ARC-Message-Signature", amsNoB).header(), headerCanon))
	if err != nil {
		return nil, fmt.Errorf("arc.Seal: sign ARC-Message-Signature: %w", err)
	}
	ams := field("ARC-Message-Signature", amsNoB+amsSig)

	// 3. ARC-Seal: signs the relaxed-canonicalized ARC header chain, with its own
	// b= empty and no trailing CRLF. arcSealBase is the exact builder Verify uses.
	//
	// The scope of the seal depends on cv (RFC 8617 §5.1.2): a cv=pass or cv=none
	// seal covers every prior ARC set plus this one, in instance order; but a
	// cv=fail seal MUST cover ONLY the ARC set this MTA just created — the prior
	// (failed) sets MUST NOT be signed. Signing the whole prior chain on a failed
	// chain is what would let a broken chain be re-sealed as if intact, healing it
	// (issue #13); it also cannot verify, since a cv=fail chain is never continued.
	asNoB := fmt.Sprintf("i=%d; a=rsa-sha256; d=%s; s=%s; t=%d; cv=%s; b=",
		instance, opt.Domain, opt.Selector, signTime, cv)
	newSet := &arcSet{aar: aar.header(), ams: ams.header(), as: field("ARC-Seal", asNoB).header()}
	sealSets := append(prior, newSet)
	if cv == "fail" {
		sealSets = []*arcSet{newSet}
	}
	asSig, err := signRSA(opt.PrivateKey, arcSealBase(sealSets))
	if err != nil {
		return nil, fmt.Errorf("arc.Seal: sign ARC-Seal: %w", err)
	}
	as := field("ARC-Seal", asNoB+asSig)

	// ARC sets are prepended highest-instance-first: seal, signature, results.
	prepended := as.raw + "\r\n" + ams.raw + "\r\n" + aar.raw + "\r\n"
	message := make([]byte, 0, len(prepended)+len(rawMessage))
	message = append(message, prepended...)
	message = append(message, rawMessage...)

	return &SealResult{
		Instance:        instance,
		ChainValidation: cv,
		AAR:             aar.raw,
		AMS:             ams.raw,
		AS:              as.raw,
		Message:         message,
	}, nil
}

// arcField is a header field being constructed for a new ARC set: its full raw
// form plus the dkim.Header the signing primitives consume.
type arcField struct {
	name  string
	value string
	raw   string
}

func field(name, value string) arcField {
	return arcField{name: name, value: value, raw: name + ": " + value}
}

// header renders the field as a dkim.Header (Value carries the post-colon SP so
// relaxed canonicalization strips it), matching what SplitMessage yields.
func (f arcField) header() *dkim.Header {
	return &dkim.Header{Name: f.name, Value: " " + f.value, Raw: f.raw}
}

// priorChain collects the existing ARC sets from a parsed header block into an
// instance-ordered slice (i=1 first) and reports the highest instance number
// present. It shares collectARCSets with Verify, so a chain carrying a duplicate
// ARC field at any instance is rejected here too (RFC 8617 §5.1.1): such a set is
// malformed and cannot be deterministically extended, so Seal refuses it rather
// than sealing over an ambiguous "last wins" choice. The slice is contiguous when
// the incoming chain is well-formed, which is the only case where cv resolves to
// "pass"; the returned highest instance is what Seal derives the new set's number
// from (max+1), which — unlike the slice length — does not collide on a gap.
func priorChain(headers []dkim.Header) ([]*arcSet, int, error) {
	sets, err := collectARCSets(headers)
	if err != nil {
		return nil, 0, err
	}
	highest := 0
	for i := range sets {
		if i > highest {
			highest = i
		}
	}
	ordered := make([]*arcSet, 0, highest)
	for i := 1; i <= highest; i++ {
		s := sets[i]
		if s == nil {
			continue
		}
		// A prior set present at this instance but missing any of its three
		// fields is structurally malformed (RFC 8617 §5.2 step 3A), the same
		// completeness rule Verify enforces. Seal cannot build the ARC-Seal base
		// over such a set — arcSealBase dereferences every field — so refuse the
		// chain with an explicit error here rather than nil-panicking downstream.
		if s.aar == nil || s.ams == nil || s.as == nil {
			return nil, 0, fmt.Errorf("i=%d incomplete ARC set", i)
		}
		ordered = append(ordered, s)
	}
	return ordered, highest, nil
}

// amsExcludedHeaders are header field names an ARC-Message-Signature h= tag MUST
// NOT list (RFC 8617 §4.1.2): the ARC-* fields — which the ARC set itself adds or
// which prior sets already carry — and Authentication-Results, a hop-local trace
// field. Binding the AMS to fields that are added or rewritten in transit would
// break the very chain the AMS anchors, so amsHeaderTag drops them even when a
// caller requests them.
var amsExcludedHeaders = map[string]bool{
	"arc-authentication-results": true,
	"arc-message-signature":      true,
	"arc-seal":                   true,
	"authentication-results":     true,
}

// amsHeaderTag builds the ARC-Message-Signature h= tag: the requested headers (or
// the default set), lowercased, filtered to those actually present and not in
// amsExcludedHeaders (RFC 8617 §4.1.2).
func amsHeaderTag(headers []dkim.Header, want []string) string {
	if len(want) == 0 {
		want = defaultAMSHeaders
	}
	present := map[string]bool{}
	for _, h := range headers {
		present[strings.ToLower(h.Name)] = true
	}
	var signed []string
	for _, name := range want {
		n := strings.ToLower(strings.TrimSpace(name))
		if n != "" && present[n] && !amsExcludedHeaders[n] {
			signed = append(signed, n)
		}
	}
	return strings.Join(signed, ":")
}

// rejectHeaderInjection refuses caller-supplied Seal inputs that carry a bare CR
// or LF, which would inject additional header fields when interpolated into the
// emitted ARC set (see Seal). Domain and Selector reach the d=/s= tags; AuthResults
// reaches the ARC-Authentication-Results content.
func rejectHeaderInjection(opt SealOptions) error {
	for _, f := range []struct{ name, val string }{
		{"Domain", opt.Domain},
		{"Selector", opt.Selector},
		{"AuthResults", opt.AuthResults},
	} {
		if strings.ContainsAny(f.val, "\r\n") {
			return fmt.Errorf("arc.Seal: %s must not contain CR or LF (header injection)", f.name)
		}
	}
	return nil
}

// signRSA hashes data with SHA-256 and returns the base64-encoded RSA signature.
func signRSA(priv *rsa.PrivateKey, data string) (string, error) {
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, dkim.HashBytes(crypto.SHA256, []byte(data)))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
