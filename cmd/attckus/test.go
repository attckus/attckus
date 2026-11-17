package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/attckus/attckus/internal/report"
	"github.com/attckus/attckus/internal/suite"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// testCmd runs a suite: every scenario runs the agent through the attckus
// gateways with faults and attacks applied, then is judged from the audit log.
func testCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suiteFile := fs.String("suite", "attckus-suite.json", "suite file")
	out := fs.String("out", "", "evidence directory (default .attckus/runs/<timestamp>)")
	format := fs.String("format", "text", "text, json or junit")
	htmlOut := fs.String("html", "", "also write an HTML report (results, and the agent's reach when a scan is set) to this file")
	strict := fs.Bool("strict", false, "treat inconclusive scenarios (attack never delivered) as failures")
	scanDir := fs.String("scan", "", "directory to scan; obeyed injections then report the agent's blast radius (default: the suite's \"scan\")")
	var only multiFlag
	fs.Var(&only, "scenario", "run only this scenario (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, err := suite.Load(*suiteFile)
	if err != nil {
		fmt.Fprintln(stderr, "attckus:", err)
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "attckus:", err)
		return 2
	}
	dir := *out
	if dir == "" {
		dir = filepath.Join(".attckus", "runs", time.Now().UTC().Format("20060102-150405"))
	}
	if dir, err = filepath.Abs(dir); err != nil {
		fmt.Fprintln(stderr, "attckus:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stderr, "attckus: testing agent %q, %d scenarios, evidence in %s\n", s.Agent, len(s.Scenarios), dir)
	r := &suite.Runner{Attckus: self, OutDir: dir, Progress: stderr}
	if *scanDir == "" {
		*scanDir = s.ScanDir()
	}
	if *scanDir != "" {
		if r.Scan, err = suite.LoadScan(*scanDir); err != nil {
			fmt.Fprintln(stderr, "attckus: scan:", err)
			return 2
		}
	}
	rep := r.Run(ctx, s, only)
	if len(rep.Results) == 0 {
		fmt.Fprintln(stderr, "attckus: no scenarios matched")
		return 2
	}
	switch *format {
	case "json":
		err = suite.JSON(stdout, rep)
	case "junit":
		err = suite.JUnit(stdout, rep)
	default:
		suite.Text(stdout, rep)
	}
	if err != nil {
		fmt.Fprintln(stderr, "attckus:", err)
		return 2
	}
	if *htmlOut != "" {
		if err := writeHTML(*htmlOut, report.HTMLData{Title: "Attckus test: " + s.Agent, Test: &rep, Scan: r.Scan}); err != nil {
			fmt.Fprintln(stderr, "attckus:", err)
			return 2
		}
		fmt.Fprintln(stderr, "attckus: HTML report in", *htmlOut)
	}
	if rep.Failed(*strict) {
		return 1
	}
	return 0
}

func writeHTML(path string, d report.HTMLData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := report.HTML(f, d); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
