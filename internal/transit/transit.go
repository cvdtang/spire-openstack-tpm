// Package transit is a crypto.Signer backed by a non-exportable OpenBao (or Vault) Transit ECDSA key.
package transit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// NewClient returns an OpenBao client for addr and token; its other settings come from the BAO_* environment.
func NewClient(addr, token string) (*api.Client, error) {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("openbao client environment: %w", cfg.Error)
	}
	cfg.Address = addr
	c, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("openbao client: %w", err)
	}
	c.SetToken(token)
	return c, nil
}

// openbaoError puts an OpenBao response error on one line for the issuer's log.
func openbaoError(err error) error {
	if re, ok := errors.AsType[*api.ResponseError](err); ok {
		return fmt.Errorf("openbao %d: %s", re.StatusCode, strings.Join(re.Errors, "; "))
	}
	return fmt.Errorf("openbao: %w", err)
}

// Signer signs with a Transit key; every request to OpenBao, Sign included, is bounded by Timeout.
type Signer struct {
	c          *api.Client
	Mount, Key string
	Timeout    time.Duration
	pub        *ecdsa.PublicKey
}

const defaultTimeout = 10 * time.Second

var hashNames = map[crypto.Hash]string{crypto.SHA256: "sha2-256", crypto.SHA384: "sha2-384", crypto.SHA512: "sha2-512"}

// NewSigner reads the latest version of an ECDSA Transit key and refuses an exportable one.
func NewSigner(ctx context.Context, c *api.Client, mount, key string) (*Signer, error) {
	s := &Signer{c: c, Mount: mount, Key: key, Timeout: defaultTimeout}
	pub, err := s.readKey(ctx)
	if err != nil {
		return nil, err
	}
	s.pub = pub
	return s, nil
}

// readKey reads the public key of the latest version and refuses an exportable or non-ECDSA key.
func (s *Signer) readKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	key := s.Key
	var out struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
			Exportable    bool   `json:"exportable"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	resp, err := s.c.Logical().ReadRawWithContext(ctx, s.Mount+"/keys/"+key)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, openbaoError(err)
	}
	if err := resp.DecodeJSON(&out); err != nil {
		return nil, fmt.Errorf("transit key %s: %w", key, err)
	}
	if out.Data.Exportable {
		return nil, fmt.Errorf("transit key %s is exportable", key)
	}
	if !strings.HasPrefix(out.Data.Type, "ecdsa-") {
		return nil, fmt.Errorf("transit key %s is %s, want an ECDSA key", key, out.Data.Type)
	}
	blk, _ := pem.Decode([]byte(out.Data.Keys[strconv.Itoa(out.Data.LatestVersion)].PublicKey))
	if blk == nil {
		return nil, fmt.Errorf("transit key %s has no public key", key)
	}
	p, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := p.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("transit key %s: public key is %T", key, p)
	}
	return ec, nil
}

// Check confirms that OpenBao is reachable, the token is valid and the key has not been rotated.
func (s *Signer) Check(ctx context.Context) error {
	pub, err := s.readKey(ctx)
	if err != nil {
		return err
	}
	if !pub.Equal(s.pub) {
		return fmt.Errorf("transit key %s was rotated", s.Key)
	}
	return nil
}

// Client is the OpenBao client the signer uses.
func (s *Signer) Client() *api.Client { return s.c }

// Public returns the key's *ecdsa.PublicKey.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign signs a prehashed digest in Transit and verifies the ASN.1 signature before returning it.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	h, ok := hashNames[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash %v", opts.HashFunc())
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, errors.New("digest length does not match the hash")
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	secret, err := s.c.Logical().WriteWithContext(ctx, s.Mount+"/sign/"+s.Key, map[string]any{
		"input": base64.StdEncoding.EncodeToString(digest), "prehashed": true,
		"hash_algorithm": h, "marshaling_algorithm": "asn1",
	})
	if err != nil {
		return nil, openbaoError(err)
	}
	var sig string // "vault:v<N>:<base64>"
	if secret != nil {
		sig, _ = secret.Data["signature"].(string)
	}
	i := strings.LastIndex(sig, ":")
	if !strings.HasPrefix(sig, "vault:v") || i < 0 {
		return nil, fmt.Errorf("transit returned a malformed signature %q", sig)
	}
	der, err := base64.StdEncoding.DecodeString(sig[i+1:])
	if err != nil || len(der) == 0 {
		return nil, fmt.Errorf("transit returned a malformed signature: %v", err)
	}
	if !ecdsa.VerifyASN1(s.pub, digest, der) {
		return nil, errors.New("transit signature does not verify with the key's public key")
	}
	return der, nil
}
