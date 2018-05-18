# Kubernetes RBAC plugin

## Overview
This purpose of this plugin is to help kubernetes admin interact
with [RBAC](https://kubernetes.io/docs/admin/authorization/rbac/) (Role-Based Access Control) and fine-tune permissions
for users and service-accounts on nodes.

## Installation
You can read about Kubernetes Plugin [here](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/).

```bash
cd ~/.kube/
mkdir plugins
cd plugins
git clone git@github.com:octarinesec/kubectl-rbac.git \
    && cd kubectl-rbac && virtualenv -p python3.6 venv && pip install -r requirements.txt
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
kubectl plugin rbac get-permissions kube-dns
```
Output
```text
[[{'apiGroups': [''],
   'resources': ['endpoints', 'services'],
   'verbs': ['list', 'watch']}]]
```
#### Get roles (cluster-roles and roles) for user/service-account
```bash
kubectl plugin rbac get-roles kube-dns
```
Output
```text
['system:kube-dns']
```
#### Get used permissions for user from audit-log
This assumes the audit log is enabled for the data you would
like to analyze.

* [k8s Documentation](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/).
* [Google Cloud](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging) specific documentation.  


```bash
kubectl plugin rbac get-audited-permissions kube-dns log.json
```
Output
```text
{'core/v1/namespaces/kube-system/configmaps/kube-dns-autoscaler': {'io.k8s.core.v1.configmaps.get'},
 'core/v1/nodes': {'io.k8s.core.v1.nodes.list'},
 'extensions/v1beta1/namespaces/kube-system/deployments/kube-dns/scale': {'io.k8s.extensions.v1beta1.deployments.scale.get'}}
```
