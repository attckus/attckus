package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/attckus/attckus/internal/capability"
)

// MCPServer is one server entry from an MCP client config.
type MCPServer struct {
	Name      string            `json:"name"`
	File      string            `json:"file"`
	Line      int               `json:"line"`
	Transport string            `json:"transport"` // stdio or http
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	URL       string            `json:"url,omitempty"`
	Env       map[string]string `json:"-"`
	Headers   map[string]string `json:"-"`

	Package string `json:"package,omitempty"` // npm/pypi package or container image
	Pinned  bool   `json:"pinned"`
	AWSRole string `json:"aws_role,omitempty"` // AWS_ROLE_ARN from env, if any

	Profile capability.ServerProfile `json:"-"`
	Known   bool                     `json:"known"`
	Kind    string                   `json:"kind"`
	Secrets []Secret                 `json:"-"`
}

// Secret is a credential written literally into a config file.
type Secret struct {
	Key      string
	Redacted string
}

// mcpConfigNames are the files MCP clients read.
var mcpConfigNames = map[string]bool{
	".mcp.json": true, "mcp.json": true, "claude_desktop_config.json": true, "mcp_config.json": true,
}

func isMCPConfig(rel string) bool {
	return mcpConfigNames[path.Base(rel)]
}

// IDEConfig reports whether a config belongs to a developer tool rather than
// a deployed agent.
func IDEConfig(rel string) bool {
	return strings.Contains(rel, ".cursor/") || strings.Contains(rel, ".vscode/") ||
		path.Base(rel) == "claude_desktop_config.json" || path.Dir(rel) == "."
}

type rawServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
	Headers map[string]string `json:"headers"`
}

// ParseMCPConfig reads Claude, Cursor and VS Code style configs
// ("mcpServers" or "servers" maps).
func ParseMCPConfig(rel string, data []byte) ([]MCPServer, error) {
	var cfg struct {
		MCPServers map[string]rawServer `json:"mcpServers"`
		Servers    map[string]rawServer `json:"servers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	all := map[string]rawServer{}
	for k, v := range cfg.Servers {
		all[k] = v
	}
	for k, v := range cfg.MCPServers {
		all[k] = v
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []MCPServer
	for _, name := range names {
		r := all[name]
		s := MCPServer{
			Name: name, File: rel, Line: lineOfKey(data, name),
			Command: r.Command, Args: r.Args, URL: r.URL, Env: r.Env, Headers: r.Headers,
			Transport: "stdio",
		}
		if r.URL != "" || r.Type == "http" || r.Type == "sse" || r.Type == "streamable-http" {
			s.Transport = "http"
		}
		s.Package, s.Pinned = packageOf(r.Command, r.Args)
		s.AWSRole = r.Env["AWS_ROLE_ARN"]
		s.Profile, s.Known = capability.ProfileFor(r.Command, r.Args, r.URL+" "+name)
		s.Kind = s.Profile.Kind
		if !s.Known {
			s.Kind = "unknown"
		}
		s.Secrets = append(findSecrets(r.Env), findSecrets(r.Headers)...)
		out = append(out, s)
	}
	return out, nil
}

func lineOfKey(data []byte, key string) int {
	needle := []byte(`"` + key + `"`)
	idx := bytes.Index(data, needle)
	if idx < 0 {
		return 1
	}
	return bytes.Count(data[:idx], []byte("\n")) + 1
}

var runners = map[string]bool{"npx": true, "uvx": true, "pipx": true, "bunx": true, "pnpx": true}

// dockerValueFlags take a separate value argument.
var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "-v": true, "--volume": true, "--name": true, "--network": true,
	"-p": true, "--publish": true, "--env-file": true, "-w": true, "--workdir": true, "--user": true, "-u": true,
	"--mount": true, "--entrypoint": true, "--platform": true,
}

// packageOf extracts the package or image a server runs and whether its
// version is pinned. Local binaries and scripts count as pinned (nothing is
// downloaded at start).
func packageOf(command string, args []string) (string, bool) {
	base := path.Base(command)
	switch {
	case runners[base] || (base == "pnpm" && len(args) > 0 && args[0] == "dlx"):
		for i, a := range args {
			if strings.HasPrefix(a, "-") || (i == 0 && a == "dlx") {
				continue
			}
			return a, pinnedPackage(a)
		}
	case base == "docker" || base == "podman":
		afterRun := false
		skip := false
		for _, a := range args {
			if skip {
				skip = false
				continue
			}
			if !afterRun {
				afterRun = a == "run"
				continue
			}
			if dockerValueFlags[a] {
				skip = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			return a, pinnedImage(a)
		}
	}
	return "", true
}

func pinnedPackage(spec string) bool {
	if strings.Contains(spec, "==") {
		return true
	}
	at := strings.LastIndex(spec, "@")
	if at <= 0 { // no version, or only the @scope prefix
		return false
	}
	v := spec[at+1:]
	return v != "" && v != "latest" && v != "next"
}

func pinnedImage(ref string) bool {
	if strings.Contains(ref, "@sha256:") {
		return true
	}
	colon := strings.LastIndex(ref, ":")
	if colon < 0 || colon < strings.LastIndex(ref, "/") {
		return false
	}
	return ref[colon+1:] != "latest"
}

var (
	secretPrefixes = regexp.MustCompile(`^(ghp_|gho_|github_pat_|glpat-|xox[abposr]-|sk-|sk-ant-|AKIA[0-9A-Z]{16}|AIza|sq0atp-|rk_live_|sk_live_|shpat_)`)
	secretKeyName  = regexp.MustCompile(`(?i)(token|secret|password|passwd|api_?key|private_?key|authorization|credential)`)
	placeholder    = regexp.MustCompile(`(?i)^(<.*>|your[-_].*|changeme|xxx+|\*+|example.*|placeholder|todo|redacted)$`)
)

func findSecrets(m map[string]string) []Secret {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Secret
	for _, k := range keys {
		v := strings.TrimSpace(m[k])
		if v == "" || strings.Contains(v, "${") || strings.HasPrefix(v, "$") || placeholder.MatchString(v) {
			continue
		}
		bare := strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "token ")
		if secretPrefixes.MatchString(bare) || (secretKeyName.MatchString(k) && len(bare) >= 12) {
			out = append(out, Secret{Key: k, Redacted: Redact(bare)})
		}
	}
	return out
}

// Redact keeps a recognisable prefix and hides the rest.
func Redact(v string) string {
	if len(v) <= 8 {
		return "REDACTED"
	}
	return v[:4] + "…REDACTED"
}
