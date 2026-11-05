// Package inventory discovers agents and MCP servers in a directory tree and
// loads the Kubernetes and AWS snapshots that sit alongside them.
package inventory

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mohitkumar/groot/internal/identity/aws"
	"github.com/mohitkumar/groot/internal/identity/k8s"
)

// AgentAnnotation marks a Kubernetes workload as an agent explicitly;
// AgentNameAnnotation links it to a code directory by name.
const (
	AgentAnnotation     = "groot.dev/agent"
	AgentNameAnnotation = "groot.dev/agent-name"
)

// llmEnvVars mark a workload as an agent when present in its environment.
var llmEnvVars = map[string]bool{
	"OPENAI_API_KEY": true, "ANTHROPIC_API_KEY": true, "GEMINI_API_KEY": true, "AZURE_OPENAI_API_KEY": true,
	"MISTRAL_API_KEY": true, "GROQ_API_KEY": true, "COHERE_API_KEY": true, "OPENROUTER_API_KEY": true,
	"LANGCHAIN_API_KEY": true, "LANGSMITH_API_KEY": true, "AWS_BEDROCK_MODEL_ID": true,
}

// Agent is one thing that calls an LLM and acts: deployed code, a cluster
// workload, a developer tool's MCP config, or a combination.
type Agent struct {
	Name     string        `json:"name"`
	Kind     string        `json:"kind"` // service or ide
	Code     *CodeAgent    `json:"code,omitempty"`
	Workload *k8s.Workload `json:"workload,omitempty"`
	Servers  []MCPServer   `json:"mcp_servers,omitempty"`
}

// Location is the best file to point a finding at.
func (a *Agent) Location() (string, int) {
	if a.Code != nil && len(a.Code.Files) > 0 {
		return a.Code.Files[0], 1
	}
	if len(a.Servers) > 0 {
		return a.Servers[0].File, a.Servers[0].Line
	}
	return "", 0
}

// Inventory is everything a scan found.
type Inventory struct {
	Root       string
	Agents     []*Agent
	K8s        *k8s.Snapshot
	K8sFiles   []string
	AWS        *aws.Snapshot
	AWSFile    string
	FilesRead  int
	Warnings   []string
	allServers []MCPServer
}

const maxFile = 20 << 20

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true, ".terraform": true, "testdata": true}

// Discover walks root and builds the inventory.
func Discover(root string) (*Inventory, error) {
	inv := &Inventory{Root: root, K8s: k8s.New()}
	code := map[string]*CodeAgent{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		ext := path.Ext(rel)
		if !isMCPConfig(rel) && ext != ".json" && rulesFor(rel) == nil {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFile {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		inv.FilesRead++
		switch {
		case isMCPConfig(rel):
			servers, err := ParseMCPConfig(rel, data)
			if err != nil {
				inv.Warnings = append(inv.Warnings, err.Error())
				return nil
			}
			inv.allServers = append(inv.allServers, servers...)
		case ext == ".json":
			inv.sniffSnapshot(rel, data)
		default:
			if rules := detectCode(rel, data); len(rules) > 0 {
				dir := path.Dir(rel)
				if code[dir] == nil {
					code[dir] = &CodeAgent{Dir: dir}
				}
				code[dir].add(rel, rules)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	inv.assemble(code)
	return inv, nil
}

func (inv *Inventory) sniffSnapshot(rel string, data []byte) {
	base := path.Base(rel)
	if base == "package.json" || base == "tsconfig.json" || strings.HasSuffix(base, "lock.json") {
		return
	}
	switch {
	case aws.LooksLike(data):
		snap, err := aws.Parse(data)
		if err != nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: %v", rel, err))
			return
		}
		if inv.AWS != nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: only one AWS snapshot is supported; using %s", rel, inv.AWSFile))
			return
		}
		inv.AWS, inv.AWSFile = snap, rel
	case k8s.LooksLike(data):
		if err := inv.K8s.Add(data); err != nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: %v", rel, err))
			return
		}
		inv.K8sFiles = append(inv.K8sFiles, rel)
	}
}

// assemble links code, configs and workloads into agents.
func (inv *Inventory) assemble(code map[string]*CodeAgent) {
	byName := map[string]*Agent{}
	get := func(name, kind string) *Agent {
		if a, ok := byName[name]; ok {
			return a
		}
		a := &Agent{Name: name, Kind: kind}
		byName[name] = a
		return a
	}

	dirs := make([]string, 0, len(code))
	for d := range code {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		c := code[d]
		if len(c.Providers) == 0 && len(c.Frameworks) == 0 {
			continue // MCP client library alone is not an agent
		}
		get(agentName(d, inv.Root), "service").Code = c
	}

	for _, s := range inv.allServers {
		dir := path.Dir(s.File)
		var a *Agent
		if c, ok := code[dir]; ok && (len(c.Providers) > 0 || len(c.Frameworks) > 0) {
			a = get(agentName(dir, inv.Root), "service")
		} else if IDEConfig(s.File) {
			a = get("ide-assistant ("+s.File+")", "ide")
		} else {
			a = get(agentName(dir, inv.Root), "service")
		}
		a.Servers = append(a.Servers, s)
	}

	for i := range inv.K8s.Workloads {
		w := inv.K8s.Workloads[i]
		if !isAgentWorkload(w) {
			continue
		}
		name := w.Name
		if n := w.Annotations[AgentNameAnnotation]; n != "" {
			name = n
		}
		a := get(name, "service")
		a.Workload = &w
	}

	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		inv.Agents = append(inv.Agents, byName[n])
	}
}

func agentName(dir, root string) string {
	if dir == "." || dir == "" {
		abs, err := filepath.Abs(root)
		if err != nil {
			return "root"
		}
		return filepath.Base(abs)
	}
	return path.Base(dir)
}

func isAgentWorkload(w k8s.Workload) bool {
	if w.Annotations[AgentAnnotation] == "true" || w.Annotations[AgentNameAnnotation] != "" {
		return true
	}
	if w.Annotations[AgentAnnotation] == "false" {
		return false
	}
	for _, e := range w.EnvNames {
		if llmEnvVars[e] {
			return true
		}
	}
	return false
}
