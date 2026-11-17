// Package aws evaluates IAM from the output of
// `aws iam get-account-authorization-details --output json`.
//
// The model is deliberately simplified and every report says so: allow
// statements are tested against a catalogue of sensitive actions, NotAction
// is supported, explicit denies with a matching action and resource remove a
// grant, and conditions are kept but marked. SCPs, permission boundaries,
// session policies and resource-based policies are not modelled yet.
package aws

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/mohitkumar/attckus/internal/capability"
)

// Snapshot is the parsed authorization details.
type Snapshot struct {
	Roles    map[string]*Role // by ARN
	byName   map[string]*Role
	policies map[string]Document // managed policies by ARN (default version)
}

type Role struct {
	Name     string
	ARN      string
	Trust    Document
	Inline   []NamedDocument
	Attached []string // managed policy ARNs
	Tags     map[string]string
}

type NamedDocument struct {
	Name string
	Doc  Document
}

// Document is an IAM policy document.
type Document struct {
	Statement []Statement
}

type Statement struct {
	Sid         string
	Effect      string
	Action      []string
	NotAction   []string
	Resource    []string
	NotResource []string
	Principal   []string // ARNs or "*" (AWS principals only)
	Conditional bool
}

// Grant is one sensitive action an identity may perform.
type Grant struct {
	Action      string
	Class       capability.Class
	Resource    string
	Conditional bool
	Via         string // policy name
}

// ---------------------------------------------------------------------------
// Parsing

type rawDetails struct {
	RoleDetailList []struct {
		RoleName                 string
		Arn                      string
		AssumeRolePolicyDocument json.RawMessage
		RolePolicyList           []struct {
			PolicyName     string
			PolicyDocument json.RawMessage
		}
		AttachedManagedPolicies []struct {
			PolicyName string
			PolicyArn  string
		}
		Tags []struct{ Key, Value string }
	}
	Policies []struct {
		PolicyName        string
		Arn               string
		DefaultVersionId  string
		PolicyVersionList []struct {
			Document         json.RawMessage
			VersionId        string
			IsDefaultVersion bool
		}
	}
}

// LooksLike reports whether raw JSON is an authorization-details export.
func LooksLike(data []byte) bool {
	var probe struct {
		RoleDetailList json.RawMessage
	}
	return json.Unmarshal(data, &probe) == nil && probe.RoleDetailList != nil
}

// Parse reads get-account-authorization-details output.
func Parse(data []byte) (*Snapshot, error) {
	var raw rawDetails
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}
	s := &Snapshot{Roles: map[string]*Role{}, byName: map[string]*Role{}, policies: map[string]Document{}}
	for _, p := range raw.Policies {
		for _, v := range p.PolicyVersionList {
			if v.IsDefaultVersion || v.VersionId == p.DefaultVersionId {
				doc, err := parseDocument(v.Document)
				if err != nil {
					return nil, fmt.Errorf("aws: policy %s: %w", p.PolicyName, err)
				}
				s.policies[p.Arn] = doc
			}
		}
	}
	for _, r := range raw.RoleDetailList {
		role := &Role{Name: r.RoleName, ARN: r.Arn, Tags: map[string]string{}}
		if len(r.AssumeRolePolicyDocument) > 0 {
			doc, err := parseDocument(r.AssumeRolePolicyDocument)
			if err != nil {
				return nil, fmt.Errorf("aws: role %s trust policy: %w", r.RoleName, err)
			}
			role.Trust = doc
		}
		for _, p := range r.RolePolicyList {
			doc, err := parseDocument(p.PolicyDocument)
			if err != nil {
				return nil, fmt.Errorf("aws: role %s policy %s: %w", r.RoleName, p.PolicyName, err)
			}
			role.Inline = append(role.Inline, NamedDocument{p.PolicyName, doc})
		}
		for _, a := range r.AttachedManagedPolicies {
			role.Attached = append(role.Attached, a.PolicyArn)
		}
		for _, t := range r.Tags {
			role.Tags[t.Key] = t.Value
		}
		s.Roles[role.ARN] = role
		s.byName[role.Name] = role
	}
	return s, nil
}

// parseDocument accepts a document as a JSON object or as a URL-encoded
// JSON string (the raw API returns the latter; the CLI decodes it).
func parseDocument(raw json.RawMessage) (Document, error) {
	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		decoded, err := url.QueryUnescape(asString)
		if err != nil {
			return Document{}, err
		}
		raw = json.RawMessage(decoded)
	}
	var doc struct {
		Statement json.RawMessage
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, err
	}
	var rawStmts []map[string]json.RawMessage
	if len(doc.Statement) > 0 && doc.Statement[0] == '{' {
		var one map[string]json.RawMessage
		if err := json.Unmarshal(doc.Statement, &one); err != nil {
			return Document{}, err
		}
		rawStmts = append(rawStmts, one)
	} else if len(doc.Statement) > 0 {
		if err := json.Unmarshal(doc.Statement, &rawStmts); err != nil {
			return Document{}, err
		}
	}
	var out Document
	for _, rs := range rawStmts {
		st := Statement{
			Effect:      str(rs["Effect"]),
			Sid:         str(rs["Sid"]),
			Action:      strList(rs["Action"]),
			NotAction:   strList(rs["NotAction"]),
			Resource:    strList(rs["Resource"]),
			NotResource: strList(rs["NotResource"]),
			Principal:   principals(rs["Principal"]),
			Conditional: len(rs["Condition"]) > 0 && string(rs["Condition"]) != "{}" && string(rs["Condition"]) != "null",
		}
		if len(st.Resource) == 0 && len(st.NotResource) == 0 {
			st.Resource = []string{"*"} // trust policies have no Resource
		}
		out.Statement = append(out.Statement, st)
	}
	return out, nil
}

func str(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func strList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

func principals(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var star string
	if json.Unmarshal(raw, &star) == nil {
		return []string{star}
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return strList(m["AWS"])
}

// ---------------------------------------------------------------------------
// Evaluation

// awsManaged covers AWS-managed policies that may be attached but absent from
// the export's Policies list.
var awsManaged = map[string]Document{
	"arn:aws:iam::aws:policy/AdministratorAccess": {Statement: []Statement{{Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}}}},
	"arn:aws:iam::aws:policy/PowerUserAccess": {Statement: []Statement{
		{Effect: "Allow", NotAction: []string{"iam:*", "organizations:*", "account:*"}, Resource: []string{"*"}}}},
	"arn:aws:iam::aws:policy/AmazonS3FullAccess":       {Statement: []Statement{{Effect: "Allow", Action: []string{"s3:*"}, Resource: []string{"*"}}}},
	"arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess": {Statement: []Statement{{Effect: "Allow", Action: []string{"dynamodb:*"}, Resource: []string{"*"}}}},
	"arn:aws:iam::aws:policy/SecretsManagerReadWrite":  {Statement: []Statement{{Effect: "Allow", Action: []string{"secretsmanager:*"}, Resource: []string{"*"}}}},
	"arn:aws:iam::aws:policy/ReadOnlyAccess":           {Statement: []Statement{{Effect: "Allow", Action: []string{"s3:Get*", "s3:List*", "dynamodb:Get*", "dynamodb:Query", "dynamodb:Scan"}, Resource: []string{"*"}}}},
}

// Role returns a role by ARN or name.
func (s *Snapshot) Role(arnOrName string) (*Role, bool) {
	if r, ok := s.Roles[arnOrName]; ok {
		return r, true
	}
	r, ok := s.byName[arnOrName]
	return r, ok
}

func (s *Snapshot) documents(r *Role) []NamedDocument {
	docs := append([]NamedDocument(nil), r.Inline...)
	for _, arn := range r.Attached {
		if d, ok := s.policies[arn]; ok {
			docs = append(docs, NamedDocument{policyName(arn), d})
		} else if d, ok := awsManaged[arn]; ok {
			docs = append(docs, NamedDocument{policyName(arn), d})
		}
	}
	return docs
}

func policyName(arn string) string { return arn[strings.LastIndex(arn, "/")+1:] }

// Grants returns every catalogue action the role may perform, by resource.
func (s *Snapshot) Grants(r *Role) []Grant {
	docs := s.documents(r)
	var denies []Statement
	for _, d := range docs {
		for _, st := range d.Doc.Statement {
			if strings.EqualFold(st.Effect, "Deny") {
				denies = append(denies, st)
			}
		}
	}
	seen := map[string]bool{}
	var out []Grant
	for _, d := range docs {
		for _, st := range d.Doc.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			for _, a := range capability.AWSActions {
				if !st.allowsAction(a.Name) {
					continue
				}
				resources := st.Resource
				if len(resources) == 0 {
					resources = []string{"*"} // NotResource: treat as broad
				}
				for _, res := range resources {
					if deniedBy(denies, a.Name, res) {
						continue
					}
					key := a.Name + "|" + res
					if seen[key] {
						continue
					}
					seen[key] = true
					out = append(out, Grant{Action: a.Name, Class: a.Class, Resource: res, Conditional: st.Conditional, Via: d.Name})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class.Rank() != out[j].Class.Rank() {
			return out[i].Class.Rank() < out[j].Class.Rank()
		}
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

func (st Statement) allowsAction(action string) bool {
	if len(st.NotAction) > 0 {
		for _, p := range st.NotAction {
			if Match(p, action, true) {
				return false
			}
		}
		return true
	}
	for _, p := range st.Action {
		if Match(p, action, true) {
			return true
		}
	}
	return false
}

// deniedBy reports whether an explicit deny covers action on resource. A
// deny counts when its resource pattern matches the granted pattern
// literally or is "*"; conditional denies are ignored (conservative: the
// grant is reported).
func deniedBy(denies []Statement, action, resource string) bool {
	for _, d := range denies {
		if d.Conditional || !d.allowsAction(action) {
			continue
		}
		for _, r := range d.Resource {
			if r == "*" || Match(r, resource, false) {
				return true
			}
		}
	}
	return false
}

// AssumableRoles returns roles r can assume: r has sts:AssumeRole on the
// target's ARN and the target's trust policy names r (or its account root).
func (s *Snapshot) AssumableRoles(r *Role) []*Role {
	var canCall []string
	for _, g := range s.Grants(r) {
		if g.Action == "sts:AssumeRole" {
			canCall = append(canCall, g.Resource)
		}
	}
	if len(canCall) == 0 {
		return nil
	}
	account := accountOf(r.ARN)
	var out []*Role
	for _, target := range s.sortedRoles() {
		if target.ARN == r.ARN {
			continue
		}
		reachable := false
		for _, pat := range canCall {
			if Match(pat, target.ARN, false) {
				reachable = true
				break
			}
		}
		if reachable && target.trusts(r.ARN, account) {
			out = append(out, target)
		}
	}
	return out
}

func (t *Role) trusts(callerARN, callerAccount string) bool {
	for _, st := range t.Trust.Statement {
		if !strings.EqualFold(st.Effect, "Allow") || !st.allowsAction("sts:AssumeRole") {
			continue
		}
		for _, p := range st.Principal {
			if p == "*" || p == callerARN || p == callerAccount ||
				p == "arn:aws:iam::"+callerAccount+":root" {
				return true
			}
		}
	}
	return false
}

func (s *Snapshot) sortedRoles() []*Role {
	out := make([]*Role, 0, len(s.Roles))
	for _, r := range s.Roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ARN < out[j].ARN })
	return out
}

func accountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}

// Match implements IAM wildcard matching: '*' matches any run of characters
// and '?' matches one. Actions match case-insensitively, ARNs do not.
func Match(pattern, s string, foldCase bool) bool {
	if foldCase {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	// Iterative glob with backtracking on the last star.
	p, i, star, mark := 0, 0, -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
