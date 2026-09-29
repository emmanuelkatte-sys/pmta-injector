# go-dkim

[![CI](https://github.com/rest-mail/go-dkim/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-dkim/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-dkim.svg)](https://pkg.go.dev/github.com/rest-mail/go-dkim)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-dkim)](https://goreportcard.com/report/github.com/rest-mail/go-dkim)

DKIM ([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)) message signing and
verification for Go — standard library only, no external dependencies.

## About

DomainKeys Identified Mail lets a domain take responsibility for a message by
attaching a cryptographic signature over selected header fields and the body. A
verifier fetches the signer's public key from DNS (at
`<selector>._domainkey.<domain>`) and confirms the message was not altered in
transit.

This package signs and verifies over the **raw** RFC 5322 message bytes — never
a parsed or reconstructed representation — so a signature is checked against
exactly what was transmitted. That is the difference between a signature that
survives real-world relays and one that only verifies against your own
serializer.

## Features

- Sign with `rsa-sha256`; verify `rsa-sha256` and legacy `rsa-sha1`, per RFC 6376.
- Both **simple** and **relaxed** header and body canonicalization.
- Operates on raw message bytes; the sign and verify paths share one canonicalizer.
- Keypair generation and DNS TXT record rendering (`GenerateKey`, `RecordValue`, `RecordFragment`).
- RFC 8601 result values (`pass`, `fail`, `neutral`, `none`, `temperror`, `permerror`).
- Pluggable DNS resolver (`TXTResolver`) for tests and custom lookups.
- Exported canonicalization primitives, so layered schemes such as ARC reuse the exact same code path.
- Zero external dependencies.

## Install

```sh
go get github.com/rest-mail/go-dkim
```

## Quickstart

A full sign-then-verify round trip. In production you generate the keypair once,
sign with the private half, and publish the public half as the DNS TXT record;
verifiers then resolve it over real DNS (pass `nil` for the resolver). Here an
in-memory resolver keeps the example self-contained.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-dkim"
)

func main() {
	// Generate a keypair (do this once; keep the private key, publish the public).
	privPEM, pubPEM, err := dkim.GenerateKey(2048)
	if err != nil {
		panic(err)
	}
	key, err := dkim.ParsePrivateKey(privPEM)
	if err != nil {
		panic(err)
	}

	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.net\r\n" +
		"Subject: hello\r\n" +
		"Date: Thu, 23 Jul 2026 10:00:00 +0000\r\n" +
		"Message-ID: <1@example.com>\r\n" +
		"\r\n" +
		"Hello, world!\r\n")

	// Sign returns the DKIM-Signature field VALUE; prepend the header yourself.
	value, err := dkim.Sign(raw, dkim.SignOptions{
		Domain:     "example.com",
		Selector:   "default",
		PrivateKey: key,
	})
	if err != nil {
		panic(err)
	}
	signed := append([]byte("DKIM-Signature: "+value+"\r\n"), raw...)

	// Verify. Pass nil for the resolver to use system DNS; here we serve the
	// public key we just generated from memory.
	txt, _ := dkim.RecordValue(pubPEM)
	resolver := func(_ context.Context, _ string) ([]string, error) {
		return []string{txt}, nil
	}
	for _, r := range dkim.Verify(context.Background(), signed, resolver) {
		fmt.Printf("d=%s s=%s -> %s\n", r.Domain, r.Selector, r.Result)
	}
	// Prints: d=example.com s=default -> pass
}
```

## Signing

`Sign` computes a DKIM-Signature field value over a raw message and returns it;
the caller prepends `DKIM-Signature: ` and a trailing CRLF. Unset `SignOptions`
fields fall back to documented defaults: `relaxed/relaxed` canonicalization and
a signed header set of `from:to:subject:date:message-id`. Only headers actually
present in the message are included in `h=`.

Generate a keypair and render its DNS TXT record with `GenerateKey`,
`RecordName`, `RecordValue` and `RecordFragment` (the last splits values over
255 characters into multiple quoted strings so 2048-bit records stay valid).

## Verifying

`Verify` returns one `VerifyResult` per DKIM-Signature header, in header order;
an empty slice means the message carried no signature. Pass `nil` for the
resolver to use system DNS, or inject a `TXTResolver` (its signature matches
`net.Resolver.LookupTXT`) in tests. Each result's `Result` field is one of
`dkim.ResultPass`, `ResultFail`, `ResultNeutral`, `ResultNone`,
`ResultTempError` or `ResultPermError` (RFC 8601 `dkim=` values).

## Primitives

The canonicalization and single-signature building blocks are exported —
`SplitMessage`, `CanonicalizeHeader`, `CanonicalizeBody`, `BuildSignedHeaders`,
`VerifySignature`, `VerifySignatureBare`, `FetchKey`, `ParseTagList`,
`ParseTagListStrict`, `RemoveBValue`, `StripWSP` and `HashBytes` — so a layered
scheme whose signature is structurally a DKIM-Signature (such as ARC's
ARC-Message-Signature) can reuse the exact same canonicalization and crypto path.

For such a scheme, prefer `VerifySignatureBare`: it runs only the cryptographic
mechanism (header/body canonicalization, hashing, and the RSA check against the
`d=`/`s=` DNS key) and applies none of the RFC 6376 DKIM-Signature policy — no
`v=` requirement, no From-signed rule, no `i=` alignment, no timing, no key-record
`t=s` / `s=` flags — so a versionless ARC-Message-Signature (RFC 8617 §4.1.2)
verifies and the scheme applies its own policy on top. `VerifySignature` is that
same primitive plus the full DKIM policy, for standalone DKIM.

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-dkim](https://pkg.go.dev/github.com/rest-mail/go-dkim).

## Changelog

Recent releases (full history and detail in [CHANGELOG.md](CHANGELOG.md)):

- **0.2.1** — add `VerifySignatureBare`, a policy-free verification primitive, restoring ARC compatibility (a versionless ARC-Message-Signature can be verified without inheriting DKIM policy).
- **0.2.0** — enforce the key record's `v=`, `s=` service-type, `t=s` no-subdomain and `h=` hash-algorithm policy; require the signature `v=` tag; require `From` in `h=` when signing; accept unpadded base64. (`FetchKey` signature changed.)
- **0.1.3** — reject `From` not signed, unaligned `i=`, duplicate tags, and expired/malformed signature timing; export `ParseTagListStrict`.
- **0.1.2** — reject a non-digit `l=` body-length tag, fixing a remotely triggerable panic.
- **0.1.1** — rename the module path to `github.com/rest-mail/go-dkim`.
- **0.1.0** — initial release: RFC 6376 signing and verification, standard library only.

## License

[MIT](LICENSE) © 2026 rest-mail
