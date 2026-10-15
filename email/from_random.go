package email

import (
	"math/rand"
	"strings"
)

// randomFromSameDomain keeps the domain part and replaces the local-part with a random token.
func randomFromSameDomain(fromAddress string) string {
	addr := strings.TrimSpace(fromAddress)
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at >= len(addr)-1 {
		return addr
	}
	return randomEmailLocalPart() + "@" + addr[at+1:]
}

// randomSubdomainSameDomain keeps the root domain and replaces or prefixes the subdomain with a random 4-letter alphanumeric string.
func randomSubdomainSameDomain(fromAddress string) string {
	addr := strings.TrimSpace(fromAddress)
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at >= len(addr)-1 {
		return addr
	}
	user := addr[:at]
	host := addr[at+1:]
	labels := strings.Split(host, ".")
	randSub := randomAlphaNum(4)
	if len(labels) >= 2 {
		rootDom := strings.Join(labels[len(labels)-2:], ".")
		return user + "@" + randSub + "." + rootDom
	}
	return user + "@" + randSub + "." + host
}

func randomEmailLocalPart() string {
	prefixes := []string{
		"noreply", "no-reply", "info", "support", "admin", "contact",
		"service", "notification", "alert", "mail", "system", "notice",
		"account", "security", "verify", "update", "billing", "help",
	}
	prefix := prefixes[rand.Intn(len(prefixes))]
	if rand.Intn(3) == 0 {
		prefix = prefix + randomAlphaNum(4)
	} else {
		prefix = prefix + randomAlphaNum(6)
	}
	return prefix
}

func randomAlphaNum(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	if n <= 0 {
		n = 6
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
