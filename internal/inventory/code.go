package inventory

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// CodeAgent is a directory whose source uses an LLM SDK or agent framework.
type CodeAgent struct {
	Dir        string   `json:"dir"`
	Files      []string `json:"files"`
	Frameworks []string `json:"frameworks,omitempty"`
	Providers  []string `json:"providers,omitempty"`
	MCPClient  bool     `json:"mcp_client"`
}

type sdkRule struct {
	re       *regexp.Regexp
	label    string
	provider bool // an LLM provider SDK rather than a framework
	mcp      bool // MCP client library
}

var pyRules = []sdkRule{
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+langgraph\b`), "LangGraph", false, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+langchain\w*`), "LangChain", false, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+crewai\b`), "CrewAI", false, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+(autogen\w*)\b`), "AutoGen", false, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+llama_index\b`), "LlamaIndex", false, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+pydantic_ai\b`), "Pydantic AI", false, false},
	{regexp.MustCompile(`(?m)^\s*from\s+agents\s+import\b`), "OpenAI Agents SDK", false, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+openai\b`), "OpenAI", true, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+anthropic\b`), "Anthropic", true, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+google\.genai\b`), "Gemini", true, false},
	{regexp.MustCompile(`(?m)^\s*(from|import)\s+mistralai\b`), "Mistral", true, false},
	{regexp.MustCompile(`(?m)^\s*from\s+mcp(\.client\S*)?\s+import\s+.*\b(ClientSession|stdio_client|streamablehttp_client|sse_client)\b`), "MCP client", false, true},
}

var jsRules = []sdkRule{
	{regexp.MustCompile(`['"]@langchain/langgraph[^'"]*['"]`), "LangGraph", false, false},
	{regexp.MustCompile(`['"](@langchain/[^'"]+|langchain)['"]`), "LangChain", false, false},
	{regexp.MustCompile(`['"]@openai/agents[^'"]*['"]`), "OpenAI Agents SDK", false, false},
	{regexp.MustCompile(`['"]@mastra/[^'"]+['"]`), "Mastra", false, false},
	{regexp.MustCompile(`['"](ai|@ai-sdk/[^'"]+)['"]`), "Vercel AI SDK", false, false},
	{regexp.MustCompile(`['"]openai['"]`), "OpenAI", true, false},
	{regexp.MustCompile(`['"]@anthropic-ai/sdk['"]`), "Anthropic", true, false},
	{regexp.MustCompile(`['"]@google/genai['"]`), "Gemini", true, false},
	{regexp.MustCompile(`['"]@modelcontextprotocol/sdk/client[^'"]*['"]`), "MCP client", false, true},
}

var goRules = []sdkRule{
	{regexp.MustCompile(`"github.com/tmc/langchaingo[^"]*"`), "LangChainGo", false, false},
	{regexp.MustCompile(`"github.com/firebase/genkit/go[^"]*"`), "Genkit", false, false},
	{regexp.MustCompile(`"github.com/anthropics/anthropic-sdk-go[^"]*"`), "Anthropic", true, false},
	{regexp.MustCompile(`"github.com/openai/openai-go[^"]*"`), "OpenAI", true, false},
	{regexp.MustCompile(`"github.com/sashabaranov/go-openai"`), "OpenAI", true, false},
	{regexp.MustCompile(`"google.golang.org/genai"`), "Gemini", true, false},
	{regexp.MustCompile(`"github.com/mark3labs/mcp-go/client[^"]*"`), "MCP client", false, true},
	{regexp.MustCompile(`"github.com/modelcontextprotocol/go-sdk/mcp"`), "MCP client", false, true},
}

// js import detection needs an import/require context to avoid matching
// any string literal "ai" or "openai".
var jsImportLine = regexp.MustCompile(`(?m)^\s*(import\b.*\bfrom\s+['"][^'"]+['"]|import\s+['"][^'"]+['"]|.*\brequire\(\s*['"][^'"]+['"]\s*\))`)

func rulesFor(rel string) []sdkRule {
	switch path.Ext(rel) {
	case ".py":
		return pyRules
	case ".ts", ".tsx", ".js", ".mjs", ".cjs":
		return jsRules
	case ".go":
		if strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		return goRules
	}
	return nil
}

// detectCode returns the SDK labels a file imports.
func detectCode(rel string, src []byte) (labels []sdkRule) {
	rules := rulesFor(rel)
	if rules == nil {
		return nil
	}
	text := string(src)
	if path.Ext(rel) != ".py" && path.Ext(rel) != ".go" {
		text = strings.Join(jsImportLine.FindAllString(text, -1), "\n")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if !seen[r.label] && r.re.MatchString(text) {
			seen[r.label] = true
			labels = append(labels, r)
		}
	}
	return labels
}

func (c *CodeAgent) add(file string, rules []sdkRule) {
	c.Files = append(c.Files, file)
	for _, r := range rules {
		switch {
		case r.mcp:
			c.MCPClient = true
		case r.provider:
			c.Providers = appendUnique(c.Providers, r.label)
		default:
			c.Frameworks = appendUnique(c.Frameworks, r.label)
		}
	}
}

func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	xs = append(xs, x)
	sort.Strings(xs)
	return xs
}
