package email

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEncodeFromAddressPHPMailer_asciiAtom(t *testing.T) {
	got := encodeFromAddressPHPMailer("Support", "a@b.com", "UTF-8")
	if got != "Support <a@b.com>" {
		t.Fatalf("got %q", got)
	}
}

func TestEncodeFromAddressPHPMailer_quotedPhrase(t *testing.T) {
	got := encodeFromAddressPHPMailer("Foo, Bar", "a@b.com", "UTF-8")
	if got != `"Foo, Bar" <a@b.com>` {
		t.Fatalf("got %q", got)
	}
}

func TestEncodeFromAddressPHPMailer_bidiUsesBAnd75(t *testing.T) {
	name := "\u2066株式会社\u202e\u2069"
	got := encodeFromAddressPHPMailer(name, "from@example.com", "UTF-8")
	if strings.Contains(got, "?Q?") {
		t.Fatalf("high 8-bit ratio should pick B, got %q", got)
	}
	if !strings.Contains(got, "?B?") {
		t.Fatalf("expected B encoding, got %q", got)
	}
	if strings.Contains(got, "quoted-printable") {
		t.Fatalf("must not use YAML header_encoding")
	}
	for _, line := range strings.Split(got, "\r\n") {
		word := strings.TrimSpace(line)
		if i := strings.Index(word, " <"); i >= 0 {
			word = word[:i]
		}
		if !strings.HasPrefix(word, "=?") {
			continue
		}
		if len(word) > 75 {
			t.Fatalf("encoded-word longer than 75: %d %q", len(word), word)
		}
	}
	if utf8.RuneCountInString(name) == len(name) {
		t.Fatal("fixture must be multibyte")
	}
}

func TestEncodeHeaderPhrase_secureCRLF(t *testing.T) {
	got := encodeFromAddressPHPMailer("A\r\nB", "x@y.z", "UTF-8")
	if strings.Contains(got, "\nB") || strings.Contains(got, "\r") {
		t.Fatalf("CRLF must be stripped from name, got %q", got)
	}
}
