package k8s

import (
	"testing"

	"github.com/mohitkumar/groot/internal/capability"
)

const list = `{"apiVersion":"v1","kind":"List","items":[
 {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"bot","namespace":"support","annotations":{"groot.dev/agent":"true"}},
  "spec":{"template":{"spec":{"serviceAccountName":"bot","containers":[{"image":"bot:1",
    "env":[{"name":"OPENAI_API_KEY","valueFrom":{"secretKeyRef":{"name":"llm-keys","key":"openai"}}}],
    "envFrom":[{"secretRef":{"name":"db-creds"}}]}]}}}},
 {"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"nightly","namespace":"ops"},
  "spec":{"jobTemplate":{"spec":{"template":{"spec":{"automountServiceAccountToken":false,"containers":[{"image":"job:1"}]}}}}}},
 {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"bot","namespace":"support",
  "annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::111122223333:role/bot"}}},
 {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"support"},
  "rules":[{"apiGroups":[""],"resources":["secrets","configmaps"],"verbs":["get","list"]}]},
 {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"bot-reader","namespace":"support"},
  "roleRef":{"kind":"Role","name":"reader"},"subjects":[{"kind":"ServiceAccount","name":"bot"}]},
 {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"deployer"},
  "rules":[{"apiGroups":["apps"],"resources":["deployments"],"verbs":["*"]}]},
 {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"all-sa-deploy"},
  "roleRef":{"kind":"ClusterRole","name":"deployer"},"subjects":[{"kind":"Group","name":"system:serviceaccounts:support"}]}
]}`

func snap(t *testing.T) *Snapshot {
	t.Helper()
	if !LooksLike([]byte(list)) {
		t.Fatal("not detected")
	}
	s := New()
	if err := s.Add([]byte(list)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWorkloads(t *testing.T) {
	s := snap(t)
	if len(s.Workloads) != 2 {
		t.Fatalf("workloads = %d", len(s.Workloads))
	}
	bot := s.Workloads[0]
	if bot.ServiceAccount != "bot" || !bot.AutomountToken || len(bot.SecretRefs) != 2 {
		t.Errorf("bot = %+v", bot)
	}
	cron := s.Workloads[1]
	if cron.ServiceAccount != "default" || cron.AutomountToken {
		t.Errorf("cronjob = %+v", cron)
	}
}

func TestIRSA(t *testing.T) {
	if got := snap(t).IRSARole("support", "bot"); got != "arn:aws:iam::111122223333:role/bot" {
		t.Errorf("irsa = %q", got)
	}
}

func TestGrants(t *testing.T) {
	gs := snap(t).Grants("support", "bot")
	classes := capability.Set{}
	var clusterDelete bool
	for _, g := range gs {
		classes[g.Class] = true
		if g.Resource == "deployments" && g.Verb == "delete" && g.Namespace == "" {
			clusterDelete = true
		}
	}
	if !classes.Has(capability.Secrets) {
		t.Error("RoleBinding grants secrets get/list")
	}
	if !clusterDelete {
		t.Error("group binding should grant cluster-wide delete on deployments")
	}
	if gs[0].Class.Rank() > gs[len(gs)-1].Class.Rank() {
		t.Error("grants not sorted by danger")
	}
	if other := snap(t).Grants("ops", "default"); len(other) != 0 {
		t.Errorf("ops/default should have no grants, got %+v", other)
	}
}
