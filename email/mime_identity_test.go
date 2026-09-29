package email

import (
	"regexp"
	"strings"
	"testing"

	"__MODULE_PLACEHOLDER__/config"
)

func TestMimeIdentity_outlookPairsNextPartWithNsHex(t *testing.T) {
	id := newMimeIdentity("outlook")
	mixed := id.boundary("Mixed")
	rel := id.boundary("Rel")
	alt := id.boundary("Alt")
	if !strings.HasPrefix(mixed, "----=_NextPart_000_") {
		t.Fatalf("mixed=%s", mixed)
	}
	if !strings.HasPrefix(rel, "----=_NextPart_001_") {
		t.Fatalf("rel=%s", rel)
	}
	if !strings.HasPrefix(alt, "----=_NextPart_002_") {
		t.Fatalf("alt=%s", alt)
	}
	suffix := strings.TrimPrefix(mixed, "----=_NextPart_000_")
	if !strings.HasSuffix(rel, suffix) || !strings.HasSuffix(alt, suffix) {
		t.Fatalf("layers must share NextPart suffix: %s / %s / %s", mixed, rel, alt)
	}
	if id.messageIDKey() != "ns_hex" {
		t.Fatalf("message-id key=%s", id.messageIDKey())
	}
}

func TestMimeIdentity_phpmailerSharesUniqueAndTimestampID(t *testing.T) {
	id := newMimeIdentity("phpmailer")
	if id.boundary("Mixed") != "b1=_"+id.unique {
		t.Fatalf("mixed=%s", id.boundary("Mixed"))
	}
	if id.boundary("Rel") != "b2=_"+id.unique {
		t.Fatalf("rel=%s", id.boundary("Rel"))
	}
	if id.boundary("Alt") != "b3=_"+id.unique {
		t.Fatalf("alt=%s", id.boundary("Alt"))
	}
	if id.messageIDKey() != "phpmailer_ts_digits" {
		t.Fatalf("message-id key=%s", id.messageIDKey())
	}
}

func TestMimeIdentity_amazonSharesPartID(t *testing.T) {
	t.Skip("amazon family commented out")
	id := newMimeIdentity("amazon")
	mixed := id.boundary("Mixed")
	rel := id.boundary("Rel")
	if !strings.HasPrefix(mixed, "----=_Part_0000001_") {
		t.Fatalf("mixed=%s", mixed)
	}
	if !strings.HasPrefix(rel, "----=_Part_0000002_") {
		t.Fatalf("rel=%s", rel)
	}
	if id.messageIDKey() != "ts_uuid_counter" {
		t.Fatalf("message-id key=%s", id.messageIDKey())
	}
}

func TestMimeIdentity_yahooMimepart(t *testing.T) {
	id := newMimeIdentity("yahoo")
	mixed := id.boundary("Mixed")
	rel := id.boundary("Rel")
	alt := id.boundary("Alt")
	re := regexp.MustCompile(`^--==_mimepart_[0-9a-f]{13}_[0-9a-f]{15}$`)
	if !re.MatchString(mixed) {
		t.Fatalf("mixed=%s", mixed)
	}
	if !re.MatchString(rel) || !re.MatchString(alt) {
		t.Fatalf("rel=%s alt=%s", rel, alt)
	}
	if mixed == rel || mixed == alt || rel == alt {
		t.Fatalf("layers must be unique mimeparts: %s / %s / %s", mixed, rel, alt)
	}
	if id.messageIDKey() != "yahoo_mimepart" {
		t.Fatalf("message-id key=%s", id.messageIDKey())
	}
	mid := id.yahooMessageID()
	if !regexp.MustCompile(`^[0-9a-f]{13}_[0-9a-f]{15}@worker\d{4}\.[a-z]+\.[a-z]+\.[a-z]+\.yahoo\.co\.jp\.mail$`).MatchString(mid) {
		t.Fatalf("message-id=%s", mid)
	}
}

func TestFamilyMessageID_matchesBoundaryFamily(t *testing.T) {
	cfg := &config.Config{}
	b := &Builder{
		cfg:       cfg,
		headerGen: NewHeaderGenerator(&cfg.Headers, 1),
	}
	cases := []struct {
		family string
		re     string
	}{
		{"outlook", `^\d+\.[0-9a-f]{12}@mail\.example\.com$`},
		// {"amazon", `^\d{8}t\d{6}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-\d{6}@mail\.example\.com$`},
		{"yahoo", `^[0-9a-f]{13}_[0-9a-f]{15}@worker\d{4}\.[a-z]+\.[a-z]+\.[a-z]+\.yahoo\.co\.jp\.mail$`},
		{"phpmailer", `^\d{34}@example\.com$`},
	}
	for _, c := range cases {
		b.mime = newMimeIdentity(c.family)
		got := b.familyMessageID("sender@mail.example.com")
		if !regexp.MustCompile(c.re).MatchString(got) {
			t.Fatalf("family=%s message-id=%s", c.family, got)
		}
	}
}
