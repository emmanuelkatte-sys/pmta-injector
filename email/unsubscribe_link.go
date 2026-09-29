package email

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/url"
	"strings"

	"__MODULE_PLACEHOLDER__/config"
)

func generateCleanLink(email, seedStr, baseURL string) (string, error) {
	recipient := strings.TrimSpace(email)
	seed := strings.TrimSpace(seedStr)
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if recipient == "" || seed == "" || base == "" {
		return "", nil
	}

	sum := sha256.Sum256([]byte(seed))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, iv, []byte(recipient), nil)
	tokenBytes := append(iv, ciphertext...)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	return base + "/" + token, nil
}

func resolveUnsubscribeBaseURL(cfg *config.HeadersConfig, boundDomain, senderEmail string) string {
	if cfg == nil {
		return ""
	}
	hostRaw := strings.TrimSpace(cfg.UnsubscribeHost)
	path := strings.TrimSpace(cfg.UnsubscribePath)
	if path == "" {
		path = "/unsubscribe"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/unsubscribe"
	}

	lower := strings.ToLower(hostRaw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(hostRaw)
		if err != nil || u.Host == "" {
			host := resolveUnsubscribeHost(cfg, boundDomain, senderEmail)
			return "https://" + host + path
		}
		scheme := u.Scheme
		if scheme == "" {
			scheme = "https"
		}
		existing := strings.TrimRight(u.Path, "/")
		fullPath := path
		if existing != "" && existing != "/" {
			fullPath = existing
		}
		return scheme + "://" + u.Host + fullPath
	}

	host := resolveUnsubscribeHost(cfg, boundDomain, senderEmail)
	return "https://" + host + path
}

func unsubscribeSeedFromConfig(cfg *config.HeadersConfig) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.UnsubscribeKey)
}
