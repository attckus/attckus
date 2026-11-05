package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mohitkumar/groot/internal/audit"
	"github.com/mohitkumar/groot/internal/chaos"
	"github.com/mohitkumar/groot/internal/llm"
	"github.com/mohitkumar/groot/internal/policy"
)

// llmCmd runs the drop-in gateway for code that calls the Anthropic or
// OpenAI APIs directly. Point the SDK at it:
//
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8788
//	OPENAI_BASE_URL=http://127.0.0.1:8788/v1
func llmCmd(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("gateway llm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyFile := fs.String("policy", "", "policy file (required)")
	agent := fs.String("agent", "agent", "default agent name; callers can override with the X-Groot-Agent header")
	auditFile := fs.String("audit", "groot-audit.jsonl", "audit log file, appended; '-' for stderr")
	env := fs.String("env", "dev", "environment name; chaos refuses to run in prod unless the policy allows it")
	listen := fs.String("listen", "127.0.0.1:8788", "listen address")
	anthropicURL := fs.String("anthropic-url", envOr("ANTHROPIC_UPSTREAM_URL", "https://api.anthropic.com"), "Anthropic API base URL")
	openaiURL := fs.String("openai-url", envOr("OPENAI_UPSTREAM_URL", "https://api.openai.com/v1"), "OpenAI-compatible API base URL")
	inject := fs.Bool("inject-keys", false, "use ANTHROPIC_API_KEY / OPENAI_API_KEY from this process instead of the caller's credentials")
	chaosOn := fs.Bool("chaos", false, "enable the policy's chaos section even if chaos.enabled is false")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyFile == "" {
		fmt.Fprintln(stderr, "groot: --policy is required (create one with: groot policy init)")
		return 2
	}
	pol, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Fprintln(stderr, "groot:", err)
		return 2
	}
	prices, err := llm.LoadPrices()
	if err != nil {
		fmt.Fprintln(stderr, "groot:", err)
		return 2
	}
	var auditOut io.Writer = stderr
	if *auditFile != "-" {
		f, err := os.OpenFile(*auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "groot:", err)
			return 2
		}
		defer f.Close()
		auditOut = f
	}
	ups := map[string]llm.Upstream{
		llm.Anthropic: {Provider: llm.Anthropic, BaseURL: *anthropicURL},
		llm.OpenAI:    {Provider: llm.OpenAI, BaseURL: *openaiURL},
	}
	if *inject {
		for name, key := range map[string]string{llm.Anthropic: os.Getenv("ANTHROPIC_API_KEY"), llm.OpenAI: os.Getenv("OPENAI_API_KEY")} {
			u := ups[name]
			u.APIKey = key
			ups[name] = u
		}
	}
	p := &llm.Proxy{
		Policy: pol, Agent: *agent, Audit: audit.NewWriter(auditOut), Prices: prices, Upstreams: ups,
		Warn:     func(s string) { fmt.Fprintln(stderr, "groot: warning:", s) },
		KillStat: func(f string) error { _, err := os.Stat(f); return err },
	}
	if pol.Chaos != nil {
		cfg := *pol.Chaos
		cfg.Enabled = cfg.Enabled || *chaosOn
		inj, err := chaos.New(cfg, *env)
		if err != nil {
			fmt.Fprintln(stderr, "groot:", err)
			return 2
		}
		p.Chaos = inj
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	fmt.Fprintf(stderr, "groot: LLM gateway on http://%s (mode %s)\n  ANTHROPIC_BASE_URL=http://%s\n  OPENAI_BASE_URL=http://%s/v1\n", *listen, pol.Mode, *listen, *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "groot:", err)
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
