package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	appserver "github.com/PrometheusMSP/PrometheusMSP-RMM/internal/server"
	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/security"
	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/store"
)

type configuration struct {
	listenAddress     string
	healthAddress     string
	databaseURL       string
	serverCertificate string
	serverKey         string
	caCertificate     string
	caKey             string
	signingKey        string
	signingKeyFile    string
	operators         map[string]security.Operator
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		err = healthcheck()
	} else {
		err = run(logger)
	}
	if err != nil {
		logger.Error("control plane stopped", "error", err)
		os.Exit(1)
	}
}

func healthcheck() error {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:8080/healthz")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}

func run(logger *slog.Logger) error {
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	database, err := store.OpenPostgres(ctx, config.databaseURL)
	if err != nil {
		return err
	}
	defer database.Close()
	caCert, err := os.ReadFile(config.caCertificate)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	caKey, err := os.ReadFile(config.caKey)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}
	ca, err := security.NewCertificateAuthority(caCert, caKey)
	if err != nil {
		return err
	}
	privateKey, err := loadJobSigningKey(config.signingKeyFile, config.signingKey)
	if err != nil { return err }
	signer, err := security.NewJobSigner(ed25519.PrivateKey(privateKey))
	if err != nil {
		return err
	}
	app, err := appserver.New(appserver.Config{
		Store: database, CA: ca, Signer: signer,
		Operators: security.NewBearerAuthenticator(config.operators), Logger: logger,
	})
	if err != nil {
		return err
	}

	serverCertificate, err := tls.LoadX509KeyPair(config.serverCertificate, config.serverKey)
	if err != nil {
		return fmt.Errorf("load server TLS key pair: %w", err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caCert) {
		return errors.New("load client CA certificate")
	}
	apiServer := &http.Server{
		Addr: config.listenAddress, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}, ClientCAs: clientRoots, ClientAuth: tls.VerifyClientCertIfGiven},
	}
	healthMux := http.NewServeMux()
	healthMux.Handle("GET /healthz", app.Handler())
	healthMux.Handle("GET /readyz", app.Handler())
	healthServer := &http.Server{Addr: config.healthAddress, Handler: healthMux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 15 * time.Second}

	errorsChannel := make(chan error, 2)
	go func() {
		logger.Info("control plane API listening", "address", config.listenAddress)
		errorsChannel <- apiServer.ListenAndServeTLS("", "")
	}()
	go func() {
		logger.Info("control plane health listener started", "address", config.healthAddress)
		errorsChannel <- healthServer.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		_ = healthServer.Shutdown(shutdownCtx)
		return apiServer.Shutdown(shutdownCtx)
	case err := <-errorsChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		listenAddress: envOr("LISTEN_ADDRESS", ":8443"), healthAddress: envOr("HEALTH_LISTEN_ADDRESS", "127.0.0.1:8080"),
		databaseURL: os.Getenv("DATABASE_URL"), serverCertificate: os.Getenv("TLS_CERT_FILE"), serverKey: os.Getenv("TLS_KEY_FILE"),
		caCertificate: os.Getenv("CA_CERT_FILE"), caKey: os.Getenv("CA_KEY_FILE"), signingKey: os.Getenv("JOB_SIGNING_KEY"), signingKeyFile: os.Getenv("JOB_SIGNING_KEY_FILE"),
	}
	required := map[string]string{
		"DATABASE_URL": config.databaseURL, "TLS_CERT_FILE": config.serverCertificate, "TLS_KEY_FILE": config.serverKey,
		"CA_CERT_FILE": config.caCertificate, "CA_KEY_FILE": config.caKey,
		"OPERATOR_TOKENS_JSON": os.Getenv("OPERATOR_TOKENS_JSON"),
	}
	if config.signingKey == "" && config.signingKeyFile == "" { return configuration{}, errors.New("JOB_SIGNING_KEY_FILE or JOB_SIGNING_KEY is required") }
	for name, value := range required {
		if value == "" {
			return configuration{}, fmt.Errorf("%s is required", name)
		}
	}
	if err := json.Unmarshal([]byte(os.Getenv("OPERATOR_TOKENS_JSON")), &config.operators); err != nil {
		return configuration{}, fmt.Errorf("parse OPERATOR_TOKENS_JSON: %w", err)
	}
	if len(config.operators) == 0 {
		return configuration{}, errors.New("at least one operator token is required")
	}
	for token, operator := range config.operators {
		if len(token) < 24 || operator.ID == "" || operator.TenantID == "" || operator.Role == "" {
			return configuration{}, errors.New("invalid operator token configuration")
		}
	}
	return config, nil
}

func loadJobSigningKey(path, encoded string) (ed25519.PrivateKey, error) {
	var data []byte
	var err error
	if path != "" { data, err = os.ReadFile(path); if err != nil { return nil, fmt.Errorf("read job signing key: %w", err) } } else { data = []byte(encoded) }
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil { return nil, fmt.Errorf("parse job signing key PEM: %w", err) }
		privateKey, ok := key.(ed25519.PrivateKey); if !ok { return nil, errors.New("job signing key is not Ed25519") }
		return privateKey, nil
	}
	value := strings.TrimSpace(string(data))
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil { decoded, err = base64.StdEncoding.DecodeString(value) }
	if err != nil || len(decoded) != ed25519.PrivateKeySize { return nil, errors.New("job signing key must be PKCS#8 PEM or base64-encoded 64-byte Ed25519 private key") }
	return ed25519.PrivateKey(decoded), nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
