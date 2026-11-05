// Package k8s resolves workloads, service accounts and RBAC from the output
// of `kubectl get deploy,sts,ds,cronjob,job,sa,role,clusterrole,rolebinding,clusterrolebinding -A -o json`.
// Several such exports can be merged.
package k8s

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mohitkumar/groot/internal/capability"
)

const IRSAAnnotation = "eks.amazonaws.com/role-arn"

// Snapshot is the parsed cluster state.
type Snapshot struct {
	Workloads       []Workload
	ServiceAccounts map[string]ServiceAccount // "ns/name"
	roles           map[string][]Rule         // "ns/name" for Role, "/name" for ClusterRole
	bindings        []binding
}

type Workload struct {
	Kind, Namespace, Name string
	ServiceAccount        string
	AutomountToken        bool
	Annotations, Labels   map[string]string
	Images                []string
	EnvNames              []string
	SecretRefs            []string // secrets mounted or referenced via env
}

func (w Workload) ID() string { return w.Namespace + "/" + w.Name }

type ServiceAccount struct {
	Namespace, Name string
	Annotations     map[string]string
}

type Rule struct {
	APIGroups, Resources, Verbs, ResourceNames []string
}

type binding struct {
	namespace string // "" for ClusterRoleBinding
	roleKind  string
	roleName  string
	subjects  []subject
	name      string
}

type subject struct{ Kind, Name, Namespace string }

// Grant is one sensitive RBAC permission.
type Grant struct {
	Verb, Resource string
	Namespace      string // "" means cluster-wide
	Class          capability.Class
	Via            string // binding name
	ResourceNames  []string
}

// ---------------------------------------------------------------------------
// Parsing

type object struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
		Labels      map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec     json.RawMessage             `json:"spec"`
	Rules    []Rule                      `json:"rules"`
	RoleRef  struct{ Kind, Name string } `json:"roleRef"`
	Subjects []subject                   `json:"subjects"`
	Items    []json.RawMessage           `json:"items"`
}

type podSpec struct {
	ServiceAccountName           string `json:"serviceAccountName"`
	DeprecatedServiceAccount     string `json:"serviceAccount"`
	AutomountServiceAccountToken *bool  `json:"automountServiceAccountToken"`
	Containers                   []struct {
		Image string `json:"image"`
		Env   []struct {
			Name      string `json:"name"`
			ValueFrom *struct {
				SecretKeyRef *struct{ Name string } `json:"secretKeyRef"`
			} `json:"valueFrom"`
		} `json:"env"`
		EnvFrom []struct {
			SecretRef *struct{ Name string } `json:"secretRef"`
		} `json:"envFrom"`
	} `json:"containers"`
	Volumes []struct {
		Secret *struct {
			SecretName string `json:"secretName"`
		} `json:"secret"`
	} `json:"volumes"`
}

// LooksLike reports whether raw JSON is a kubectl List or a single object.
func LooksLike(data []byte) bool {
	var probe struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.Kind != "" && probe.APIVersion != ""
}

func New() *Snapshot {
	return &Snapshot{ServiceAccounts: map[string]ServiceAccount{}, roles: map[string][]Rule{}}
}

// Add merges one kubectl JSON export into the snapshot.
func (s *Snapshot) Add(data []byte) error {
	var top object
	if err := json.Unmarshal(data, &top); err != nil {
		return fmt.Errorf("k8s: %w", err)
	}
	if top.Kind == "List" || strings.HasSuffix(top.Kind, "List") {
		for _, item := range top.Items {
			if err := s.Add(item); err != nil {
				return err
			}
		}
		return nil
	}
	return s.addObject(top)
}

func (s *Snapshot) addObject(o object) error {
	ns, name := o.Metadata.Namespace, o.Metadata.Name
	switch o.Kind {
	case "ServiceAccount":
		s.ServiceAccounts[ns+"/"+name] = ServiceAccount{Namespace: ns, Name: name, Annotations: o.Metadata.Annotations}
	case "Role":
		s.roles[ns+"/"+name] = o.Rules
	case "ClusterRole":
		s.roles["/"+name] = o.Rules
	case "RoleBinding", "ClusterRoleBinding":
		b := binding{roleKind: o.RoleRef.Kind, roleName: o.RoleRef.Name, subjects: o.Subjects, name: name}
		if o.Kind == "RoleBinding" {
			b.namespace = ns
		}
		s.bindings = append(s.bindings, b)
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet":
		spec, err := extractPodSpec(o.Kind, o.Spec)
		if err != nil {
			return fmt.Errorf("k8s: %s %s/%s: %w", o.Kind, ns, name, err)
		}
		if o.Kind == "ReplicaSet" || (o.Kind == "Pod" && len(o.Metadata.Labels["pod-template-hash"]) > 0) {
			return nil // owned by a Deployment we already see
		}
		s.Workloads = append(s.Workloads, toWorkload(o, spec))
	}
	return nil
}

func extractPodSpec(kind string, raw json.RawMessage) (podSpec, error) {
	var ps podSpec
	if len(raw) == 0 {
		return ps, nil
	}
	switch kind {
	case "Pod":
		return ps, json.Unmarshal(raw, &ps)
	case "CronJob":
		var cj struct {
			JobTemplate struct {
				Spec struct {
					Template struct{ Spec podSpec } `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		}
		err := json.Unmarshal(raw, &cj)
		return cj.JobTemplate.Spec.Template.Spec, err
	default:
		var w struct {
			Template struct{ Spec podSpec } `json:"template"`
		}
		err := json.Unmarshal(raw, &w)
		return w.Template.Spec, err
	}
}

func toWorkload(o object, ps podSpec) Workload {
	sa := ps.ServiceAccountName
	if sa == "" {
		sa = ps.DeprecatedServiceAccount
	}
	if sa == "" {
		sa = "default"
	}
	w := Workload{
		Kind: o.Kind, Namespace: o.Metadata.Namespace, Name: o.Metadata.Name,
		ServiceAccount: sa, AutomountToken: ps.AutomountServiceAccountToken == nil || *ps.AutomountServiceAccountToken,
		Annotations: o.Metadata.Annotations, Labels: o.Metadata.Labels,
	}
	secrets := map[string]bool{}
	for _, c := range ps.Containers {
		w.Images = append(w.Images, c.Image)
		for _, e := range c.Env {
			w.EnvNames = append(w.EnvNames, e.Name)
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				secrets[e.ValueFrom.SecretKeyRef.Name] = true
			}
		}
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil {
				secrets[ef.SecretRef.Name] = true
			}
		}
	}
	for _, v := range ps.Volumes {
		if v.Secret != nil {
			secrets[v.Secret.SecretName] = true
		}
	}
	for name := range secrets {
		w.SecretRefs = append(w.SecretRefs, name)
	}
	sort.Strings(w.SecretRefs)
	return w
}

// ---------------------------------------------------------------------------
// Resolution

// IRSARole returns the AWS role ARN annotated on a service account.
func (s *Snapshot) IRSARole(namespace, name string) string {
	return s.ServiceAccounts[namespace+"/"+name].Annotations[IRSAAnnotation]
}

// Grants returns the sensitive RBAC permissions of a service account,
// expanding wildcards and group subjects (system:serviceaccounts, etc.).
func (s *Snapshot) Grants(namespace, name string) []Grant {
	seen := map[string]bool{}
	var out []Grant
	for _, b := range s.bindings {
		if !b.boundTo(namespace, name) {
			continue
		}
		var rules []Rule
		if b.roleKind == "ClusterRole" {
			rules = s.roles["/"+b.roleName]
		} else {
			rules = s.roles[b.namespace+"/"+b.roleName]
		}
		for _, r := range rules {
			for _, verb := range expand(r.Verbs, capability.K8sVerbs) {
				for _, res := range expand(r.Resources, capability.K8sResources) {
					class, ok := capability.K8sClass(verb, res)
					if !ok {
						continue
					}
					key := b.namespace + "|" + verb + "|" + res + "|" + strings.Join(r.ResourceNames, ",")
					if seen[key] {
						continue
					}
					seen[key] = true
					out = append(out, Grant{Verb: verb, Resource: res, Namespace: b.namespace, Class: class,
						Via: b.kind() + "/" + b.name, ResourceNames: r.ResourceNames})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class.Rank() != out[j].Class.Rank() {
			return out[i].Class.Rank() < out[j].Class.Rank()
		}
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].Verb < out[j].Verb
	})
	return out
}

func (b binding) kind() string {
	if b.namespace == "" {
		return "ClusterRoleBinding"
	}
	return "RoleBinding"
}

func (b binding) boundTo(namespace, name string) bool {
	for _, sub := range b.subjects {
		switch sub.Kind {
		case "ServiceAccount":
			subNS := sub.Namespace
			if subNS == "" {
				subNS = b.namespace
			}
			if sub.Name == name && subNS == namespace {
				return true
			}
		case "Group":
			if sub.Name == "system:serviceaccounts" || sub.Name == "system:authenticated" ||
				sub.Name == "system:serviceaccounts:"+namespace {
				return true
			}
		case "User":
			if sub.Name == "system:serviceaccount:"+namespace+":"+name {
				return true
			}
		}
	}
	return false
}

func expand(values, universe []string) []string {
	for _, v := range values {
		if v == "*" {
			return universe
		}
	}
	return values
}

// IsAdmin reports whether grants include full control of everything.
func IsAdmin(gs []Grant) bool {
	for _, g := range gs {
		if g.Class == capability.Admin {
			return true
		}
	}
	return false
}
