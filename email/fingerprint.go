package email

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"

	"__MODULE_PLACEHOLDER__/config"
)

var mimeFamilies = []string{
	"outlook",
	// "amazon",
	"yahoo",
	"phpmailer",
}

// identityFingerprint 由发信身份组成，不含 job / 收件人 / 时间。
// 同一 IP（同一 hostname / 发信域）跨任务保持同一客户端指纹。
func identityFingerprint(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	var parts []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			parts = append(parts, s)
		}
	}
	add(cfg.Headers.MessageIDFullDomain)
	add(cfg.Headers.MessageIDMainDomain)
	if cfg.Template.GlobalVariables != nil {
		if v, ok := cfg.Template.GlobalVariables["server_hostname"]; ok {
			add(fmt.Sprint(v))
		}
	}
	add(cfg.SMTP.Host)
	add(cfg.PMTA.VirtualMTA)
	from := strings.TrimSpace(cfg.Sender.FromAddress)
	if i := strings.LastIndex(from, "@"); i >= 0 {
		add(from[i+1:])
	} else {
		add(from)
	}
	add(cfg.Headers.ClientProfile)
	return strings.Join(parts, "|")
}

func identityRNG(cfg *config.Config, purpose string) *rand.Rand {
	return rand.New(rand.NewSource(hashSeed(identityFingerprint(cfg) + "|" + purpose)))
}

func identityIndex(cfg *config.Config, purpose string, n int) int {
	if n <= 0 {
		return 0
	}
	return safeIntn(identityRNG(cfg, purpose), n)
}

func (hg *HeaderGenerator) identityKey() string {
	if hg == nil {
		return ""
	}
	if strings.TrimSpace(hg.fingerprintKey) != "" {
		return hg.fingerprintKey
	}
	if hg.cfg == nil {
		return ""
	}
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(hg.cfg.MessageIDFullDomain),
		strings.TrimSpace(hg.cfg.MessageIDMainDomain),
		strings.TrimSpace(hg.cfg.ClientProfile),
	}, "|"))
}

func (hg *HeaderGenerator) identityRand(purpose string) *rand.Rand {
	return rand.New(rand.NewSource(hashSeed(hg.identityKey() + "|" + purpose)))
}

func (hg *HeaderGenerator) identityIndex(purpose string, n int) int {
	if n <= 0 {
		return 0
	}
	return safeIntn(hg.identityRand(purpose), n)
}

func mutatorSeed(cfg *config.Config, templatePath string) string {
	return identityFingerprint(cfg) + "|" + filepath.Base(strings.TrimSpace(templatePath))
}
