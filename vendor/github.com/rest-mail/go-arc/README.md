# go-arc

[![CI](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-arc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-arc.svg)](https://pkg.go.dev/github.com/rest-mail/go-arc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-arc)](https://goreportcard.com/report/github.com/rest-mail/go-arc)

Authenticated Received Chain ([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617))
sealing and verification for Go.

## About

ARC lets a message's authentication assessment survive intermediaries — mailing
lists, forwarders, and other relays that legitimately modify a message and so
break its original DKIM signature or SPF alignment. Each participating hop
records what it saw by prepending an ARC set of three header fields:
`ARC-Authentication-Results`, `ARC-Message-Signature`, and `ARC-Seal`. A
downstream receiver can then cryptographically confirm the whole chain and trust
the earliest hop's assessment even though DKIM or SPF no longer pass directly.

This package does both sides of ARC over the **raw** RFC 5322 message bytes —
never a parsed or reconstructed representation. `arc.Verify` checks an existing
chain against exactly what was transmitted; `arc.Seal` adds a new ARC set as a
forwarder would, and what `Seal` produces `Verify` accepts.

## Features

- **Sealing** (`arc.Seal`): add an ARC set — `ARC-Authentication-Results`,
  `ARC-Message-Signature`, `ARC-Seal` — for instance `i=N`, with `cv=` computed
  by verifying the chain being extended (`none`/`pass`/`fail`). Returns the
  message with the set prepended, ready to relay.
- **Verifying** (`arc.Verify`): full RFC 8617 §5.2 chain verification — the most
  recent `ARC-Message-Signature` over the message, plus every `ARC-Seal` over the
  ARC header chain up to its instance.
- Structural validation: ARC sets must be numbered contiguously `1..N`, each set
  complete.
- Returns an RFC 8617 chain-validation status — `pass`, `fail`, or `none` — with
  a human-readable reason.
- Operates on raw message bytes, the same bytes DKIM signs and verifies.
- Pluggable DNS resolver (`dkim.TXTResolver`) for tests and custom lookups; `nil`
  uses the system resolver.
- Built on [github.com/rest-mail/go-dkim](https://github.com/rest-mail/go-dkim) —
  its only dependency — so ARC shares DKIM's exact canonicalization and crypto
  path (`rsa-sha256`, relaxed canonicalization); sealing reuses the DKIM key.

## Install

```sh
go get github.com/rest-mail/go-arc
```

## Quickstart

Seal a message as a forwarder would, then verify the result — the round trip a
downstream receiver relies on. In production you would publish the public key as
a DNS TXT record and pass `nil` for the resolver (system DNS); here an in-memory
resolver serves the key so the example is self-contained.

```go
package main

import (
	"context"
	"fmt"

	arc "github.com/rest-mail/go-arc"
	"github.com/rest-mail/go-dkim"
)

func main() {
	// Keep the private key for signing; publish the public half as the DNS record.
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

	// Serve the public key from memory so the round trip needs no real DNS.
	// In production, pass nil to use the system resolver.
	txt, _ := dkim.RecordValue(pubPEM)
	resolver := func(_ context.Context, name string) ([]string, error) {
		if name == dkim.RecordName("arc", "example.com") {
			return []string{txt}, nil
		}
		return nil, fmt.Errorf("no record for %s", name)
	}

	// Seal: add an ARC set as this hop. cv= is computed from the incoming chain
	// (none here — no prior sets).
	res, err := arc.Seal(context.Background(), raw, arc.SealOptions{
		Domain:      "example.com",
		Selector:    "arc",
		PrivateKey:  key,
		AuthResults: "example.com; spf=pass smtp.mailfrom=alice@example.com",
		Resolver:    resolver,
	})
	if err != nil {
		panic(err)
	}

	// Verify what we just sealed.
	cv, reason := arc.Verify(context.Background(), res.Message, resolver)
	fmt.Printf("sealed i=%d cv=%s -> verify %s: %s\n", res.Instance, res.ChainValidation, cv, reason)
	// Prints: sealed i=1 cv=none -> verify pass: ARC chain cryptographically verified (1 set(s))
}
```

## Sealing

`arc.Seal` adds one ARC set for the next hop:

```go
func Seal(ctx context.Context, rawMessage []byte, opt SealOptions) (*SealResult, error)
```

`SealOptions` takes the signing identity — `Domain`, `Selector`, and
`PrivateKey` (a `*rsa.PrivateKey`, e.g. from `dkim.ParsePrivateKey`) — plus the
`AuthResults` to record and optional canonicalization / `Headers` / `Time` /
`Resolver` settings. It:

- picks the next instance `i=N` from the ARC sets already in the message;
- computes `cv=` by verifying the chain it is extending — `none` with no prior
  chain, else the `pass`/`fail` `Verify` reports (this is the only time `Seal`
  needs the resolver / DNS);
- builds the three header fields and returns a `*SealResult` whose `Message` is
  `rawMessage` with the new set prepended, ready to relay (the individual `AAR`,
  `AMS`, and `AS` fields and the `Instance` / `ChainValidation` are exposed too).

The signing key is reused from DKIM: an `ARC-Message-Signature` is a
`DKIM-Signature` and an `ARC-Seal` a DKIM-style signature over the ARC header
chain, both `rsa-sha256`.

## Verifying

`arc.Verify` is the whole public surface:

```go
func Verify(ctx context.Context, rawMessage []byte, resolver dkim.TXTResolver) (cv, reason string)
```

It returns a chain-validation status (`"pass"`, `"fail"`, or `"none"`) and a
human-readable reason. Feed the status into a downstream `Authentication-Results`
header as `arc=<cv>`. Pass `nil` for the resolver to use system DNS, or inject a
`dkim.TXTResolver` (its signature matches `net.Resolver.LookupTXT`) in tests.

An `ARC-Message-Signature` is structurally a DKIM-Signature and an `ARC-Seal` is
a DKIM-style signature over the ARC header fields, so this package reuses the
canonicalization and signature primitives exported by go-dkim rather than
reimplementing them — ARC verification is therefore byte-for-byte consistent with
DKIM verification over the same message.

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-arc](https://pkg.go.dev/github.com/rest-mail/go-arc).

## Changelog

Recent releases (see [CHANGELOG.md](CHANGELOG.md) for the full history):

- **v0.2.3** — Verify now requires the ARC-Message-Signature to sign From
  (RFC 8617 §5.1.1); an AMS whose `h=` omits From is treated as cv=fail.
- **v0.2.2** — restore ARC-Message-Signature verification via go-dkim v0.2.1's
  policy-free primitive (fixing the regression from DKIM's `v=` requirement);
  RFC 8617 verify/seal fixes: 50-set cap, `cv=fail` seal scope, reject seal `h=`,
  require seal `s=`/`d=`, instance-from-highest, strict instance/tag parsing.
- **v0.2.1** — validate the ARC-Seal `cv=` chain, reject repeated ARC fields,
  ignore an unexpected AMS `v=`; go-dkim v0.1.2.
- **v0.2.0** — see the [release notes](https://github.com/rest-mail/go-arc/releases/tag/v0.2.0).
- **v0.1.1** — see the [release notes](https://github.com/rest-mail/go-arc/releases/tag/v0.1.1).
- **v0.1.0** — initial release: ARC sealing and verification (RFC 8617).

## License

[MIT](LICENSE) © 2026 rest-mail
