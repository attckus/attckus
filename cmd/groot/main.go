// Command groot finds what AI agents can break and stops them doing it.
//
//	groot scan [flags] [dir]        blast-radius scan of agents and MCP servers
//	groot graph [dir]               Mermaid graph of every agent's reach
//	groot gateway stdio [flags] -- <server command...>
//	groot gateway http [flags] --upstream <url>
//	groot analyze [flags] <audit.jsonl>
//	groot policy init|check
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mohitkumar/groot/internal/analyze"
	"github.com/mohitkumar/groot/internal/attack"
	"github.com/mohitkumar/groot/internal/audit"
	"github.com/mohitkumar/groot/internal/chaos"
	"github.com/mohitkumar/groot/internal/gateway"
	"github.com/mohitkumar/groot/internal/inventory"
	"github.com/mohitkumar/groot/internal/policy"
	"github.com/mohitkumar/groot/internal/report"
	"github.com/mohitkumar/groot/internal/risk"
)

const version = "0.2.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "scan":
		return scan(args[1:], stdout, stderr, "")
	case "graph":
		return scan(args[1:], stdout, stderr, "mermaid")
	case "test":
		return testCmd(args[1:], stdout, stderr)
	case "gateway":
		return gatewayCmd(args[1:], stdin, stdout, stderr)
	case "analyze":
		return analyzeCmd(args[1:], stdout, stderr)
	case "policy":
		return policyCmd(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "groot", version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `groot: find what your AI agents can break, and stop them

Usage:
  groot test [--suite groot-suite.json] [--format text|json|junit] [--scenario name] [--out dir] [--strict]
  groot scan [--format text|json|sarif|mermaid] [--fail-on critical|high|medium|low|none] [dir]
  groot graph [dir]
  groot gateway stdio --policy p.json [--agent name] [--audit file] [--env dev] -- <server command...>
  groot gateway http  --policy p.json --upstream URL [--listen :8787] [--agent name] [--audit file]
  groot gateway llm   --policy p.json [--listen :8788] [--agent name] [--audit file] [--inject-keys]
  groot analyze [--format text|json] [--retry-threshold 5] [--window 60s] audit.jsonl
  groot policy init [--out policy.json]
  groot policy check policy.json
  groot version

Scan reads MCP configs, agent code, and exported snapshots in dir:
  kubectl get deploy,sts,ds,cronjob,job,sa,role,clusterrole,rolebinding,clusterrolebinding -A -o json > k8s.json
  aws iam get-account-authorization-details --output json > iam.json
`)
}

// ---------------------------------------------------------------------------
// scan

func scan(args []string, stdout, stderr io.Writer, forceFormat string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text, json, sarif or mermaid")
	failOn := fs.String("fail-on", "critical", "exit 1 at this severity or above: critical, high, medium, low or none")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if forceFormat != "" {
		*format, *failOn = forceFormat, "none"
	}
	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	var threshold risk.Severity
	if *failOn != "none" {
		var err error
		if threshold, err = risk.ParseSeverity(*failOn); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	inv, err := inventory.Discover(root)
	if err != nil {
		fmt.Fprintln(stderr, "scan:", err)
		return 2
	}
	for _, w := range inv.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	res := risk.Analyze(inv)

	switch *format {
	case "text":
		report.Text(stdout, res)
	case "json":
		err = report.JSON(stdout, res)
	case "sarif":
		err = report.SARIF(stdout, res, version)
	case "mermaid":
		report.Mermaid(stdout, res)
	default:
		fmt.Fprintf(stderr, "unknown format %q\n", *format)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *failOn != "none" {
		for _, f := range res.Findings {
			if f.Severity >= threshold {
				return 1
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// gateway

type gatewayFlags struct {
	policyFile, agent, server, auditFile, env string
	attacksFile, canary                       string
	chaos                                     bool
}

func (g *gatewayFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&g.policyFile, "policy", "", "policy file (required)")
	fs.StringVar(&g.agent, "agent", "agent", "agent name used in rules and audit")
	fs.StringVar(&g.server, "server-name", "", "upstream server name used in rules and audit (default: derived)")
	fs.StringVar(&g.auditFile, "audit", "groot-audit.jsonl", "audit log file, appended; '-' for stderr")
	fs.StringVar(&g.env, "env", "dev", "environment name; chaos refuses to run in prod unless the policy allows it")
	fs.BoolVar(&g.chaos, "chaos", false, "enable the policy's chaos section even if chaos.enabled is false")
	fs.StringVar(&g.attacksFile, "attacks", "", "attacks file (set by groot test)")
	fs.StringVar(&g.canary, "canary", "", "canary token for attacks (set by groot test)")
}

func (g *gatewayFlags) engine(stderr io.Writer) (*gateway.Engine, func(), error) {
	if g.policyFile == "" {
		return nil, nil, errors.New("--policy is required (create one with: groot policy init)")
	}
	p, err := policy.Load(g.policyFile)
	if err != nil {
		return nil, nil, err
	}
	var auditOut io.Writer = stderr
	closer := func() {}
	if g.auditFile != "-" {
		f, err := os.OpenFile(g.auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, err
		}
		auditOut, closer = f, func() { f.Close() }
	}
	e := gateway.New(p, g.agent, g.server)
	e.Audit = audit.NewWriter(auditOut)
	e.Warn = func(s string) { fmt.Fprintln(stderr, "groot: warning:", s) }
	if p.Chaos != nil {
		cfg := *p.Chaos
		cfg.Enabled = cfg.Enabled || g.chaos
		inj, err := chaos.New(cfg, g.env)
		if err != nil {
			closer()
			return nil, nil, err
		}
		e.Chaos = inj
		if inj != nil {
			fmt.Fprintf(stderr, "groot: chaos enabled (seed %d, %d faults)\n", cfg.Seed, len(cfg.Faults))
		}
	} else if g.chaos {
		closer()
		return nil, nil, errors.New("--chaos given but the policy has no chaos section")
	}
	if g.attacksFile != "" {
		data, err := os.ReadFile(g.attacksFile)
		if err != nil {
			closer()
			return nil, nil, err
		}
		var attacks []attack.Attack
		if err := json.Unmarshal(data, &attacks); err != nil {
			closer()
			return nil, nil, fmt.Errorf("attacks: %w", err)
		}
		if e.Attacks, err = attack.New(attacks, g.canary); err != nil {
			closer()
			return nil, nil, err
		}
	}
	fmt.Fprintf(stderr, "groot: gateway for agent %q, server %q, mode %s\n", g.agent, e.Server, p.Mode)
	return e, closer, nil
}

func gatewayCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "llm" {
		return llmCmd(args[1:], stderr)
	}
	if len(args) == 0 || (args[0] != "stdio" && args[0] != "http") {
		fmt.Fprintln(stderr, "usage: groot gateway stdio|http|llm [flags]")
		return 2
	}
	mode := args[0]
	fs := flag.NewFlagSet("gateway "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var g gatewayFlags
	g.register(fs)
	upstream := fs.String("upstream", "", "upstream MCP server URL (http mode)")
	listen := fs.String("listen", "127.0.0.1:8787", "listen address (http mode)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if mode == "stdio" {
		cmdArgs := fs.Args()
		if len(cmdArgs) == 0 {
			fmt.Fprintln(stderr, "usage: groot gateway stdio --policy p.json -- <server command...>")
			return 2
		}
		if g.server == "" {
			g.server = filepath.Base(cmdArgs[0])
		}
		e, closeAudit, err := g.engine(stderr)
		if err != nil {
			fmt.Fprintln(stderr, "groot:", err)
			return 2
		}
		defer closeAudit()
		return runStdio(ctx, e, cmdArgs, stdin, stdout, stderr)
	}

	if *upstream == "" {
		fmt.Fprintln(stderr, "groot: --upstream is required in http mode")
		return 2
	}
	u, err := url.Parse(*upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		fmt.Fprintf(stderr, "groot: bad --upstream %q\n", *upstream)
		return 2
	}
	if g.server == "" {
		g.server = u.Hostname()
	}
	e, closeAudit, err := g.engine(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "groot:", err)
		return 2
	}
	defer closeAudit()
	srv := &http.Server{Addr: *listen, Handler: &gateway.HTTPProxy{Engine: e, Upstream: u}, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	fmt.Fprintf(stderr, "groot: listening on http://%s, forwarding to %s\n", *listen, u)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "groot:", err)
		return 1
	}
	return 0
}

func runStdio(ctx context.Context, e *gateway.Engine, cmdArgs []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stderr = stderr
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(stderr, "groot:", err)
		return 1
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(stderr, "groot:", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "groot: starting server:", err)
		return 1
	}
	serveErr := gateway.ServeStdio(ctx, e, stdin, stdout, serverIn, serverOut)
	waitErr := cmd.Wait()
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		fmt.Fprintln(stderr, "groot:", serveErr)
		return 1
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	return 0
}

// ---------------------------------------------------------------------------
// analyze

func analyzeCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text or json")
	threshold := fs.Int("retry-threshold", 5, "identical calls within the window that count as a retry storm")
	window := fs.Duration("window", 60*time.Second, "window for retry storms and escalation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: groot analyze [flags] audit.jsonl")
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer f.Close()
	events, err := audit.Read(f)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	rep := analyze.Run(events, analyze.Options{RetryThreshold: *threshold, Window: *window})
	if *format == "json" {
		if err := analyze.JSON(stdout, rep); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		analyze.Text(stdout, rep)
	}
	for _, is := range rep.Issues {
		if is.Severity == "critical" || is.Severity == "high" {
			return 1
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// policy

func policyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: groot policy init|check")
		return 2
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("policy init", flag.ContinueOnError)
		fs.SetOutput(stderr)
		out := fs.String("out", "", "write to this file instead of stdout")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		b, _ := json.MarshalIndent(policy.Default(), "", "  ")
		b = append(b, '\n')
		if *out == "" {
			_, _ = stdout.Write(b)
			return 0
		}
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(stderr, "%s exists; not overwriting\n", *out)
			return 1
		}
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stderr, "wrote %s (dry-run mode; switch \"mode\" to \"enforce\" when ready)\n", *out)
		return 0
	case "check":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: groot policy check policy.json")
			return 2
		}
		p, err := policy.Load(args[1])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		chaosNote := "no chaos"
		if p.Chaos != nil {
			chaosNote = fmt.Sprintf("chaos enabled=%v with %d faults", p.Chaos.Enabled, len(p.Chaos.Faults))
		}
		fmt.Fprintf(stdout, "ok: %d rules, mode %s, default %s, %s\n", len(p.Rules), p.Mode, p.Default, chaosNote)
		return 0
	}
	fmt.Fprintf(stderr, "unknown policy command %q\n", args[0])
	return 2
}
