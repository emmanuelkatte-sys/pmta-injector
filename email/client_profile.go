package email

import (
	"crypto/sha256"
	"strings"
)

// ClientProfile bundles per-client fingerprint pools (stable per subdomain, rotate per message).
type ClientProfile struct {
	Key             string
	XMailers        []string
	MessageIDStyles []string
	UserAgents      []string
}

var (
	clientProfileKeys = []string{"outlook", "apple", "thunderbird", "gmail", "becky", "emclient"}
	clientProfiles    map[string]ClientProfile
)

func init() {
	clientProfiles = map[string]ClientProfile{
		"outlook": {
			Key:             "outlook",
			XMailers:        filterMailers(containsAny("outlook", "office outlook", "windows live mail")),
			MessageIDStyles: []string{"uuid_v4_upper", "readable_ts", "ts_uuid_counter", "enterprise_multiseg", "uuid_seq"},
			UserAgents: []string{
				"Microsoft-MacOutlook/16.81.0 (Mac OS/13.6; Build/16.81.0)",
				"Microsoft-MacOutlook/16.80.0 (Mac OS/14.1; Build/16.80.0)",
				"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro)",
				"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.16924; Pro)",
				"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook for Office 365 MSO/16.0)",
			},
		},
		"apple": {
			Key:             "apple",
			XMailers:        filterMailers(containsAny("apple mail", "iphone mail", "ipad mail", "mail (mac os x")),
			MessageIDStyles: []string{"uuid_v4_lower", "hex32", "compact_date_ns", "ns_hex", "mixed_alnum"},
			UserAgents: []string{
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Mail/16.0",
				"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
				"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Mail/3449.100.1",
			},
		},
		"thunderbird": {
			Key:             "thunderbird",
			XMailers:        filterMailers(containsAny("thunderbird")),
			MessageIDStyles: []string{"hex32", "exim", "sendmail", "hex_underscore", "epoch_counter"},
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Thunderbird/115.4.1",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Thunderbird/115.5.0",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:115.0) Gecko/20100101 Thunderbird/115.4.1",
				"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Thunderbird/102.15.1",
			},
		},
		"gmail": {
			Key:             "gmail",
			XMailers:        filterMailers(containsAny("gmail", "google workspace")),
			MessageIDStyles: []string{"base64url", "mixed_alnum", "tag_uuid", "bigint_hex", "hex16"},
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
				"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
			},
		},
		"becky": {
			Key:             "becky",
			XMailers:        filterMailers(containsAny("becky")),
			MessageIDStyles: []string{"becky", "javamail", "hex16", "ms_ts_hex", "uuid_v4_lower"},
			UserAgents: []string{
				"Becky! ver. 2.74.01 [ja]",
				"Becky! Internet Mail 2.80.07",
				"Becky! Internet Mail 2.80.08",
			},
		},
		"emclient": {
			Key:             "emclient",
			XMailers:        filterMailers(containsAny("em client", "mailbird", "postbox")),
			MessageIDStyles: []string{"javamail", "uuid_v4_lower", "enterprise_multiseg", "biz_prefix", "uuid_v1"},
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) eM Client/9.2.2159.0",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) eM Client/9.1.2108.0",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) eM Client/9.2.2159.0",
			},
		},
	}
	for key, p := range clientProfiles {
		if len(p.XMailers) == 0 {
			p.XMailers = append([]string(nil), xMailerList...)
			clientProfiles[key] = p
		}
	}
}

func containsAny(parts ...string) func(string) bool {
	return func(s string) bool {
		lower := strings.ToLower(s)
		for _, p := range parts {
			if strings.Contains(lower, strings.ToLower(p)) {
				return true
			}
		}
		return false
	}
}

func filterMailers(match func(string) bool) []string {
	out := make([]string, 0, 32)
	for _, m := range xMailerList {
		if match(m) {
			out = append(out, m)
		}
	}
	return out
}

// ResolveClientProfile maps a mail subdomain to a stable client profile key.
func ResolveClientProfile(subdomain string) string {
	sub := strings.TrimSpace(strings.ToLower(subdomain))
	if sub == "" {
		sub = "mail"
	}
	sum := sha256.Sum256([]byte(sub))
	return clientProfileKeys[int(sum[0])%len(clientProfileKeys)]
}

func lookupClientProfile(key string) (ClientProfile, bool) {
	key = strings.TrimSpace(strings.ToLower(key))
	if key == "" {
		return ClientProfile{}, false
	}
	p, ok := clientProfiles[key]
	return p, ok
}

func (hg *HeaderGenerator) activeClientProfile() (ClientProfile, bool) {
	if hg.cfg == nil {
		return ClientProfile{}, false
	}
	key := strings.TrimSpace(hg.cfg.ClientProfile)
	if key == "" {
		return ClientProfile{}, false
	}
	return lookupClientProfile(key)
}

func (hg *HeaderGenerator) getProfileXMailer() string {
	if p, ok := hg.activeClientProfile(); ok && len(p.XMailers) > 0 {
		return p.XMailers[hg.identityIndex("xmailer", len(p.XMailers))]
	}
	return hg.getRandomXMailer()
}

func (hg *HeaderGenerator) getProfileUserAgent() string {
	if p, ok := hg.activeClientProfile(); ok && len(p.UserAgents) > 0 {
		return p.UserAgents[hg.identityIndex("user-agent", len(p.UserAgents))]
	}
	return ""
}

func (hg *HeaderGenerator) messageIDStyleCandidates() []string {
	if p, ok := hg.activeClientProfile(); ok && len(p.MessageIDStyles) > 0 {
		return p.MessageIDStyles
	}
	candidates := messageIDStyleKeys
	if hg.cfg != nil && !hg.cfg.MessageIDRandomAll && len(hg.cfg.MessageIDStyles) > 0 {
		sel := make(map[string]bool, len(hg.cfg.MessageIDStyles))
		for _, s := range hg.cfg.MessageIDStyles {
			sel[strings.TrimSpace(s)] = true
		}
		filtered := make([]string, 0, len(messageIDStyleKeys))
		for _, k := range messageIDStyleKeys {
			if sel[k] {
				filtered = append(filtered, k)
			}
		}
		if len(filtered) > 0 {
			candidates = filtered
		}
	}
	return candidates
}
