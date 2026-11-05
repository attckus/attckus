package capability

import "strings"

// Action is a concrete cloud API action with its class.
type Action struct {
	Name  string // e.g. "s3:DeleteObject"
	Class Class
}

// AWSActions is the catalogue of sensitive AWS actions. IAM statements are
// tested against it: a statement granting "s3:*" matches s3:DeleteObject,
// s3:GetObject and so on, which is how wildcards are resolved to classes.
// It is deliberately small; extend it as findings demand.
var AWSActions = []Action{
	// admin: change permissions or assume other identities
	{"iam:PassRole", Admin}, {"iam:CreateRole", Admin}, {"iam:CreateUser", Admin},
	{"iam:CreateAccessKey", Admin}, {"iam:AttachRolePolicy", Admin}, {"iam:AttachUserPolicy", Admin},
	{"iam:PutRolePolicy", Admin}, {"iam:PutUserPolicy", Admin}, {"iam:UpdateAssumeRolePolicy", Admin},
	{"iam:CreatePolicyVersion", Admin}, {"sts:AssumeRole", Admin},
	// exec: run code
	{"ssm:SendCommand", Exec}, {"ssm:StartSession", Exec}, {"lambda:UpdateFunctionCode", Exec},
	{"lambda:CreateFunction", Exec}, {"lambda:InvokeFunction", Exec}, {"ec2:RunInstances", Exec},
	{"ecs:RunTask", Exec}, {"ecs:ExecuteCommand", Exec},
	// destroy
	{"s3:DeleteObject", Destroy}, {"s3:DeleteBucket", Destroy}, {"s3:PutLifecycleConfiguration", Destroy},
	{"dynamodb:DeleteTable", Destroy}, {"dynamodb:DeleteItem", Destroy},
	{"rds:DeleteDBInstance", Destroy}, {"rds:DeleteDBCluster", Destroy},
	{"ec2:TerminateInstances", Destroy}, {"ec2:DeleteVolume", Destroy}, {"ec2:DeleteSnapshot", Destroy},
	{"kms:ScheduleKeyDeletion", Destroy}, {"kms:DisableKey", Destroy},
	{"logs:DeleteLogGroup", Destroy}, {"cloudtrail:StopLogging", Destroy}, {"cloudtrail:DeleteTrail", Destroy},
	// secrets
	{"secretsmanager:GetSecretValue", Secrets}, {"ssm:GetParameter", Secrets}, {"ssm:GetParameters", Secrets},
	{"ssm:GetParametersByPath", Secrets}, {"kms:Decrypt", Secrets},
	// write
	{"s3:PutObject", Write}, {"s3:PutBucketPolicy", Write}, {"dynamodb:PutItem", Write},
	{"dynamodb:UpdateItem", Write}, {"rds:ModifyDBInstance", Write}, {"sqs:SendMessage", Write},
	{"sns:Publish", External}, {"ses:SendEmail", External}, {"ses:SendRawEmail", External},
	// read private data
	{"s3:GetObject", Read}, {"s3:ListBucket", Read}, {"dynamodb:GetItem", Read}, {"dynamodb:Query", Read},
	{"dynamodb:Scan", Read}, {"rds-data:ExecuteStatement", Read}, {"athena:StartQueryExecution", Read},
	{"sqs:ReceiveMessage", Read},
}

// K8sClass classifies a Kubernetes RBAC verb on a resource.
func K8sClass(verb, resource string) (Class, bool) {
	verb, resource = strings.ToLower(verb), strings.ToLower(resource)
	switch {
	case verb == "bind" || verb == "escalate" || verb == "impersonate":
		return Admin, true
	case (resource == "roles" || resource == "clusterroles" || resource == "rolebindings" || resource == "clusterrolebindings") &&
		(verb == "create" || verb == "update" || verb == "patch"):
		return Admin, true
	case resource == "pods/exec" || resource == "pods/attach" || (resource == "pods" && verb == "create"):
		// Creating a pod lets you mount any service account in the namespace.
		return Exec, true
	case resource == "secrets" && (verb == "get" || verb == "list" || verb == "watch"):
		return Secrets, true
	case verb == "delete" || verb == "deletecollection":
		return Destroy, true
	case verb == "create" || verb == "update" || verb == "patch":
		return Write, true
	case verb == "get" || verb == "list" || verb == "watch":
		return Read, true
	}
	return "", false
}

// K8sVerbs and K8sResources are what wildcards expand to when evaluating RBAC.
var (
	K8sVerbs     = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "bind", "escalate", "impersonate"}
	K8sResources = []string{"secrets", "pods", "pods/exec", "deployments", "statefulsets", "configmaps", "services",
		"persistentvolumeclaims", "namespaces", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts"}
)
