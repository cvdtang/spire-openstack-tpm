// Command openstack-tpm-issuer serves the provider's issuer and, with `ca`, prints the CA certificate of its issuing key.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/caarlos0/env/v11"
	"golang.org/x/sync/errgroup"

	"github.com/cvdtang/openstack-tpm/internal/contract"
	"github.com/cvdtang/openstack-tpm/internal/issuer"
	"github.com/cvdtang/openstack-tpm/internal/openstack"
	"github.com/cvdtang/openstack-tpm/internal/transit"
)

const usage = "usage: openstack-tpm-issuer [ca [-cn NAME]]"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "openstack-tpm-issuer:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return serve(ctx)
	}
	switch args[0] {
	case "ca":
		return caCommand(ctx, args[1:], stdout)
	}
	return fmt.Errorf("unknown command %q; %s", args[0], usage)
}

// transitConfig is where the issuing key is, for serving and for `ca`.
type transitConfig struct {
	Addr       string `env:"BAO_ADDR" envDefault:"http://127.0.0.1:8200"`
	Token      string `env:"BAO_TOKEN,notEmpty"`
	Mount      string `env:"ISSUER_TRANSIT_MOUNT" envDefault:"transit"`
	IssuingKey string `env:"ISSUER_ISSUING_KEY" envDefault:"issuing"`
}

// issuingSigner connects to OpenBao and reads the issuing key.
func (t transitConfig) issuingSigner(ctx context.Context) (*transit.Signer, error) {
	bao, err := transit.NewClient(t.Addr, t.Token)
	if err != nil {
		return nil, err
	}
	s, err := transit.NewSigner(ctx, bao, t.Mount, t.IssuingKey)
	if err != nil {
		return nil, fmt.Errorf("ISSUER_ISSUING_KEY: %w", err)
	}
	return s, nil
}

// config is the issuer's environment. An empty variable counts as unset.
type config struct {
	Transit      transitConfig
	IssuingCert  string `env:"ISSUER_ISSUING_CERT,notEmpty"`
	ClearKey     string `env:"ISSUER_CLEAR_KEY" envDefault:"clear"`
	Region       string `env:"ISSUER_REGION,notEmpty"`
	ClientCA     string `env:"ISSUER_CLIENT_CA,notEmpty"`
	Listen       string `env:"ISSUER_LISTEN" envDefault:":8443"`
	HealthListen string `env:"ISSUER_HEALTH_LISTEN" envDefault:"127.0.0.1:8098"`
	TLSCert      string `env:"ISSUER_TLS_CERT,notEmpty"`
	TLSKey       string `env:"ISSUER_TLS_KEY,notEmpty"`
	OS           struct {
		AuthURL           string `env:"OS_AUTH_URL,notEmpty"`
		Username          string `env:"OS_USERNAME,notEmpty"`
		Password          string `env:"OS_PASSWORD,notEmpty"`
		UserDomainName    string `env:"OS_USER_DOMAIN_NAME" envDefault:"Default"`
		ProjectName       string `env:"OS_PROJECT_NAME,notEmpty"`
		ProjectDomainName string `env:"OS_PROJECT_DOMAIN_NAME" envDefault:"Default"`
	}
}

func loadConfig() (*config, error) {
	c := &config{}
	if err := parseEnv(c); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *config) credentials() openstack.Credentials {
	o := c.OS
	return openstack.Credentials{
		AuthURL: o.AuthURL, Username: o.Username, Password: o.Password, UserDomainName: o.UserDomainName,
		ProjectName: o.ProjectName, ProjectDomainName: o.ProjectDomainName,
	}
}

// parseEnv fills v from the environment and names every missing variable in one error.
func parseEnv(v any) error {
	err := env.Parse(v)
	var agg env.AggregateError
	if !errors.As(err, &agg) {
		return err
	}
	var missing []string
	for _, e := range agg.Errors {
		var empty env.EmptyVarError
		if !errors.As(e, &empty) {
			return err
		}
		missing = append(missing, empty.Key)
	}
	return fmt.Errorf("missing environment: %s", strings.Join(missing, ", "))
}

// runtime is what the startup checks leave for serving.
type runtime struct {
	issuing, clear *transit.Signer
	issuingCert    *x509.Certificate
	clientCAs      *x509.CertPool
	tlsCert        tls.Certificate
}

// setup reads the keys and files and refuses a configuration the issuer cannot serve with.
func setup(ctx context.Context, cfg *config) (*runtime, error) {
	// The issuing key signs under the CA certificate that `openstack-tpm-issuer ca` made for it.
	issuing, err := cfg.Transit.issuingSigner(ctx)
	if err != nil {
		return nil, err
	}
	certs, err := contract.ReadCertificates(cfg.IssuingCert)
	if err != nil {
		return nil, fmt.Errorf("ISSUER_ISSUING_CERT: %w", err)
	}
	if !issuing.Public().(*ecdsa.PublicKey).Equal(certs[0].PublicKey) || !certs[0].IsCA {
		return nil, fmt.Errorf("ISSUER_ISSUING_CERT: %q is not a CA certificate for transit key %s", certs[0].Subject, cfg.Transit.IssuingKey)
	}
	// The clear key authorizes TPM2_Clear on nodes and must be ECDSA P-256, which every TPM verifies.
	clear, err := transit.NewSigner(ctx, issuing.Client(), cfg.Transit.Mount, cfg.ClearKey)
	if err != nil {
		return nil, fmt.Errorf("ISSUER_CLEAR_KEY: %w", err)
	}
	if clear.Public().(*ecdsa.PublicKey).Curve != elliptic.P256() {
		return nil, errors.New("ISSUER_CLEAR_KEY must be an ECDSA P-256 Transit key")
	}
	clientCA, err := os.ReadFile(cfg.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("ISSUER_CLIENT_CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCA) {
		return nil, errors.New("ISSUER_CLIENT_CA: no certificates")
	}
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("ISSUER_TLS_CERT/KEY: %w", err)
	}
	return &runtime{issuing: issuing, clear: clear, issuingCert: certs[0], clientCAs: pool, tlsCert: tlsCert}, nil
}

func serve(ctx context.Context) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	rt, err := setup(ctx, cfg)
	if err != nil {
		return err
	}

	is := &issuer.Service{
		Region:      cfg.Region,
		Cloud:       issuer.NewOpenStack(openstack.New(cfg.credentials(), openstack.Endpoints{Region: cfg.Region, Interface: "internal"}, 5*time.Second)),
		IssuingCert: rt.issuingCert, Issuing: rt.issuing, ClearSigner: rt.clear,
		Log: log, Now: time.Now,
	}
	srv := &http.Server{
		Addr: cfg.Listen, Handler: is.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
		// Compute hosts present a client certificate of the hosts' CA, which the VM endpoint requires; the IPA ramdisk has none.
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{rt.tlsCert},
			ClientAuth:   tls.VerifyClientCertIfGiven, ClientCAs: rt.clientCAs, MinVersion: tls.VersionTLS13,
		},
	}
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// Healthy means OpenBao is reachable, the token valid and both keys unchanged.
		for _, k := range []*transit.Signer{rt.issuing, rt.clear} {
			if err := k.Check(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		fmt.Fprintln(w, "ok")
	})
	health := &http.Server{Addr: cfg.HealthListen, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}

	// Both listeners run until a signal or until one fails, then both shut down.
	g, gctx := errgroup.WithContext(ctx)
	listen := func(name string, serve func() error) {
		g.Go(func() error {
			if err := serve(); !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		})
	}
	listen("health listener", health.ListenAndServe)
	listen("listener", func() error { return srv.ListenAndServeTLS("", "") })
	g.Go(func() error {
		<-gctx.Done()
		if ctx.Err() != nil {
			log.Info("shutting down")
		}
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = health.Shutdown(sctx)
		return srv.Shutdown(sctx)
	})
	log.Info("listening", "addr", cfg.Listen, "health", cfg.HealthListen,
		"issuing_key", cfg.Transit.IssuingKey, "issuing_cert", rt.issuingCert.Subject.String(), "region", cfg.Region)
	return g.Wait()
}

// caCommand prints the self-signed CA certificate of the issuing key, which needs only the issuer's own Transit policy.
func caCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	cn := fs.String("cn", "openstack-tpm issuing", "subject common name")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: openstack-tpm-issuer ca [-cn NAME]

Prints the self-signed CA certificate of the Transit issuing key (BAO_ADDR, BAO_TOKEN,
ISSUER_TRANSIT_MOUNT, ISSUER_ISSUING_KEY).
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("ca: unexpected argument %q", fs.Arg(0))
	}
	var tc transitConfig
	if err := parseEnv(&tc); err != nil {
		return err
	}
	signer, err := tc.issuingSigner(ctx)
	if err != nil {
		return err
	}
	der, err := selfSigned(signer, *cn, time.Now())
	if err != nil {
		return err
	}
	return pem.Encode(stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// selfSigned makes the trust anchor, a non-expiring certificate of the issuing key signed by itself.
func selfSigned(signer crypto.Signer, cn string, now time.Time) ([]byte, error) {
	serial, err := contract.NewSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"openstack-tpm"}},
		NotBefore:             now.Add(-5 * time.Minute).UTC().Truncate(time.Second),
		NotAfter:              contract.NotAfter(),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
}
