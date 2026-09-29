package email

import (
	"strings"
	"testing"
)

func TestFoldArcFieldRFC5322(t *testing.T) {
	bval := strings.Repeat("A", 200)
	raw := "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=dkim; t=1700000000; cv=none; b=" + bval
	out := foldArcFieldRFC5322(raw)
	if !strings.HasSuffix(out, "\r\n") {
		t.Fatal("missing trailing CRLF")
	}
	lines := strings.Split(strings.TrimSuffix(out, "\r\n"), "\r\n")
	if len(lines) < 2 {
		t.Fatalf("expected folded lines, got %q", out)
	}
	for i, line := range lines {
		if len(line) > rfc5322HardLine {
			t.Fatalf("line exceeds 998: %d", len(line))
		}
		if i > 0 && (line == "" || (line[0] != ' ' && line[0] != '\t')) {
			t.Fatalf("continuation must start with WSP: %q", line)
		}
		if i > 0 && len(line) > rfc5322SoftLine+1 {
			t.Fatalf("soft line too long: %d %q", len(line), line)
		}
	}
	got := strings.ReplaceAll(strings.TrimSuffix(out, "\r\n"), "\r\n ", "")
	if got != raw {
		t.Fatalf("fold changed non-FWS bytes:\n got %q\nwant %q", got, raw)
	}
}

func TestFoldArcFieldShort(t *testing.T) {
	raw := "ARC-Authentication-Results: i=1; example.com; none"
	out := foldArcFieldRFC5322(raw)
	if out != raw+"\r\n" {
		t.Fatalf("short field should stay one line, got %q", out)
	}
}

func TestArcInBValueNotBH(t *testing.T) {
	v := "i=1; bh=" + strings.Repeat("B", 40) + "; b=" + strings.Repeat("C", 40)
	if arcInBValue(v, strings.Index(v, "bh=")) {
		t.Fatal("bh= must not be treated as b=")
	}
	if !arcInBValue(v, strings.Index(v, "; b=")+2) {
		t.Fatal("b= value must be detected")
	}
}
