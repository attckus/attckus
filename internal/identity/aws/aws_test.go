package aws

import (
	"strings"
	"testing"

	"github.com/mohitkumar/groot/internal/capability"
)

const fixture = `{
  "RoleDetailList": [
    {
      "RoleName": "agent",
      "Arn": "arn:aws:iam::111122223333:role/agent",
      "AssumeRolePolicyDocument": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"oidc"},"Action":"sts:AssumeRoleWithWebIdentity"}]},
      "RolePolicyList": [
        {"PolicyName": "data", "PolicyDocument": {"Statement": [
          {"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::orders-prod","arn:aws:s3:::orders-prod/*"]},
          {"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"support"}}},
          {"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111122223333:role/ops-*"},
          {"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}
        ]}}
      ],
      "AttachedManagedPolicies": [],
      "Tags": []
    },
    {
      "RoleName": "ops-admin",
      "Arn": "arn:aws:iam::111122223333:role/ops-admin",
      "AssumeRolePolicyDocument": "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fagent%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "RolePolicyList": [],
      "AttachedManagedPolicies": [{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]
    },
    {
      "RoleName": "ops-readonly",
      "Arn": "arn:aws:iam::111122223333:role/ops-readonly",
      "AssumeRolePolicyDocument": {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]},
      "RolePolicyList": [],
      "AttachedManagedPolicies": [{"PolicyName":"local","PolicyArn":"arn:aws:iam::111122223333:policy/local"}]
    }
  ],
  "Policies": [
    {"PolicyName":"local","Arn":"arn:aws:iam::111122223333:policy/local","DefaultVersionId":"v2",
     "PolicyVersionList":[
       {"VersionId":"v1","IsDefaultVersion":false,"Document":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}},
       {"VersionId":"v2","IsDefaultVersion":true,"Document":{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}}
     ]}
  ]
}`

func load(t *testing.T) *Snapshot {
	t.Helper()
	if !LooksLike([]byte(fixture)) {
		t.Fatal("fixture not detected")
	}
	s, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func find(gs []Grant, action, resource string) (Grant, bool) {
	for _, g := range gs {
		if g.Action == action && g.Resource == resource {
			return g, true
		}
	}
	return Grant{}, false
}

func TestGrantsResolveWildcardsAndDenies(t *testing.T) {
	s := load(t)
	agent, _ := s.Role("agent")
	gs := s.Grants(agent)
	if _, ok := find(gs, "s3:DeleteObject", "arn:aws:s3:::orders-prod/*"); !ok {
		t.Error("s3:* should grant s3:DeleteObject")
	}
	if _, ok := find(gs, "s3:DeleteBucket", "arn:aws:s3:::orders-prod"); ok {
		t.Error("explicit deny should remove s3:DeleteBucket")
	}
	g, ok := find(gs, "secretsmanager:GetSecretValue", "*")
	if !ok || !g.Conditional || g.Class != capability.Secrets {
		t.Errorf("conditional secrets grant: %+v %v", g, ok)
	}
	if gs[0].Class != capability.Admin {
		t.Errorf("grants should sort most dangerous first, got %s", gs[0].Class)
	}
}

func TestManagedPolicyDefaultVersion(t *testing.T) {
	s := load(t)
	ro, _ := s.Role("ops-readonly")
	gs := s.Grants(ro)
	if len(gs) != 1 || gs[0].Action != "s3:GetObject" {
		t.Errorf("only the default version should count, got %+v", gs)
	}
}

func TestAWSManagedAdmin(t *testing.T) {
	s := load(t)
	admin, _ := s.Role("ops-admin")
	if _, ok := find(s.Grants(admin), "iam:PassRole", "*"); !ok {
		t.Error("AdministratorAccess should grant iam:PassRole")
	}
}

func TestAssumableRoles(t *testing.T) {
	s := load(t)
	agent, _ := s.Role("agent")
	got := s.AssumableRoles(agent)
	if len(got) != 1 || got[0].Name != "ops-admin" {
		names := []string{}
		for _, r := range got {
			names = append(names, r.Name)
		}
		t.Fatalf("assumable = %v, want [ops-admin] (ops-readonly does not trust agent)", names)
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		p, s string
		fold bool
		want bool
	}{
		{"s3:*", "s3:DeleteObject", true, true},
		{"S3:get*", "s3:GetObject", true, true},
		{"s3:Get*", "s3:PutObject", true, false},
		{"*", "anything", false, true},
		{"arn:aws:s3:::orders-*/*", "arn:aws:s3:::orders-prod/*", false, true},
		{"arn:aws:s3:::orders-prod", "arn:aws:s3:::orders-prod/*", false, false},
		{"iam:?assRole", "iam:PassRole", true, true},
		{"*Object", "s3:GetObject", true, true},
		{"a*b*c", "aXXbYYc", false, true},
		{"a*b*c", "aXXbYY", false, false},
	}
	for _, c := range cases {
		if got := Match(c.p, c.s, c.fold); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.p, c.s, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte(`{"RoleDetailList": [{"RoleName":"x","RolePolicyList":[{"PolicyName":"p","PolicyDocument":"%ZZ"}]}]}`)); err == nil || !strings.Contains(err.Error(), "role x") {
		t.Errorf("want error naming the role, got %v", err)
	}
}
