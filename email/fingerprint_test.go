package email

import (
	"testing"

	"__MODULE_PLACEHOLDER__/config"
)

func TestIdentityFingerprint_ignoresJobAndRecipient(t *testing.T) {
	cfg := &config.Config{}
	cfg.Headers.MessageIDFullDomain = "mail.example.com"
	cfg.Sender.FromAddress = "news@mail.example.com"
	cfg.Job.ID = "job-aaa"
	a := identityFingerprint(cfg)
	cfg.Job.ID = "job-bbb"
	b := identityFingerprint(cfg)
	if a == "" || a != b {
		t.Fatalf("fingerprint must ignore job id: %q vs %q", a, b)
	}
}

func TestLockedMimeFamily_stableAcrossBuilders(t *testing.T) {
	cfg := &config.Config{}
	cfg.Headers.MessageIDFullDomain = "mail.example.com"
	cfg.Sender.FromAddress = "news@mail.example.com"
	one := (&Builder{cfg: cfg}).lockedMimeFamily()
	two := (&Builder{cfg: cfg}).lockedMimeFamily()
	if one != two {
		t.Fatalf("family changed: %s vs %s", one, two)
	}
	found := false
	for _, f := range mimeFamilies {
		if f == one {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unexpected family %s", one)
	}
}

func TestMutatorSeed_usesBasenameNotTaskPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Headers.MessageIDFullDomain = "mail.example.com"
	a := mutatorSeed(cfg, "/tmp/task-aaa/templates/promo.html")
	b := mutatorSeed(cfg, "/tmp/task-bbb/templates/promo.html")
	if a != b {
		t.Fatalf("task path leaked into mutator seed: %q vs %q", a, b)
	}
}
