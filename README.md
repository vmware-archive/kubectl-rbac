# Kubernetes RBAC plugin

## Overview
This purpose of this plugin is to help kubernetes admin interact
with [RBAC](https://kubernetes.io/docs/admin/authorization/rbac/) (Role-Based Access Control) and fine-tune permissions
for users and service-accounts on pods.

You can take a look at the [blogpost](https://medium.com/@haim_50405/establish-least-privileged-best-practice-for-your-kubernetes-clusters-f0785e1aee39) where we go through basic concepts of RBAC and motiviation for this tool

## Installation
This tool can used as a standalone tool or k8s plugin.
You can read about Kubernetes Plugin framework [here](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/).

```bash
cd ~/.kube/
mkdir plugins
cd plugins
git clone git@github.com:octarinesec/kubectl-rbac.git \
    && cd kubectl-rbac && virtualenv -p python3.6 venv && source venv/bin/activate && pip install -r requirements.txt
```

## Example & Usage
#### Help
```bash
kubectl plugin rbac --help
```
Output:
```text
Inspect RBAC related properties

Available Commands:
  get-audited-permissions Get used permissions as audited in the audit-log
  get-permissions         Get permissions for user
  get-roles               Get roles for user

Usage:
  kubectl plugin rbac [options]

Use "kubectl <command> --help" for more information about a given command.
Use "kubectl options" for a list of global command-line options (applies to all commands).
```
#### Get Permissions for user/service-account
```bash
kubectl plugin rbac get-permissions user@octarinesec.com
```
Output
```text
[[{'apiGroups': [''],
  'resources': ['clusterrolebindings',
                'clusterroles',
                'roles',
                'rolebindings'],
  'verbs': ['list']
  },
 {'apiGroups': [''],
  'resources': ['clusterroles', 'clusterrolebindings'],
  'verbs': ['get']
  }]]
```

#### Get roles (cluster-roles and roles) for user/service-account
```bash
kubectl plugin rbac get-roles user@octarinesec.com
```
Output
```text
['octarine-role:user@octarinesec.com']
```
#### Get used permissions for user from audit-log
This assumes the audit log is enabled for the data you would
like to analyze.

* [k8s Documentation](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/).
* [Google Cloud](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging) specific documentation.  


```bash
kubectl plugin rbac get-audited-permissions user@octarinesec.com kubectl_rbac/tests/audit_log.json
```
Output
```text
 {...
 'rbac.authorization.k8s.io/v1/clusterroles/system:basic-user': {'io.k8s.authorization.rbac.v1.clusterroles.get'},
 'rbac.authorization.k8s.io/v1/clusterroles/system:certificates.k8s.io:certificatesigningrequests:nodeclient': {'io.k8s.authorization.rbac.v1.clusterroles.get'},
 'rbac.authorization.k8s.io/v1/clusterroles/system:certificates.k8s.io:certificatesigningrequests:selfnodeclient': {'io.k8s.authorization.rbac.v1.clusterroles.get'},
 'rbac.authorization.k8s.io/v1/clusterroles/system:controller:attachdetach-controller': {'io.k8s.authorization.rbac.v1.clusterroles.get'},
 'rbac.authorization.k8s.io/v1/namespaces/default/rolebindings': {'io.k8s.authorization.rbac.v1.rolebindings.list'},
 'rbac.authorization.k8s.io/v1/namespaces/default/roles': {'io.k8s.authorization.rbac.v1.roles.list'}}
```

#### Get least privilege yaml for specific user based on the audit log
```bash
kubectl plugin rbac get-least-privilege user@octarinesec.com kubectl_rbac/tests/audit_log.json
```
Output
```text
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: octarine:user@octarinesec.com
  namespace: default
rules:
- apiGroups:
  - ''
  resources:
  - clusterroles
  - clusterrolebindings
  - rolebindings
  - roles
  verbs:
  - list
- apiGroups:
  - ''
  resources:
  - clusterroles
  - clusterrolebindings
  verbs:
  - get

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: octarine:user@octarinesec.com
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: octarine:user@octarinesec.com
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: user@octarinesec.com
```

You can pipe this output to roles.yaml and run ```bash kubectl -f create roles.yaml```

#### Get unused privileges for specific user based on the audit log
```bash
kubectl plugin rbac get-unused-permissions user@octarinesec.com kubectl_rbac/tests/audit_log.json
```
Output
```text
{'create': set(),
 'delete': set(),
 'get': set(),
 'list': set(),
 'patch': set(),
 'update': set(),
 'watch': set()}
```
We can see that our user is configured properly and he has the least privilege permissions

## Testing
```text
nosetests
```
