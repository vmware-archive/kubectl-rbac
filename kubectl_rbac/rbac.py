import os
import yaml
import json
import copy
import pprint
import argparse
import subprocess
from collections import defaultdict


NAMESPACE = os.environ.get('KUBECTL_PLUGINS_CURRENT_NAMESPACE')
KUBECTL_PATH = os.environ.get('KUBECTL_PLUGINS_CALLER')


class RBAC(object):
    def __init__(self, namespace, kubectl_path):
        self._namespace = namespace
        self._kubectl_path = kubectl_path

    @staticmethod
    def _get_verb_to_resource(role):
        verbs = ["get", "list", "watch", "create", "update", "patch", "delete"]
        verb_to_resource = {k: set() for k in verbs}
        for rule in role['rules']:
            for verb in rule['verbs']:
                verb_to_resource[verb] = verb_to_resource[verb].union(rule['resources'])
        return verb_to_resource

    @staticmethod
    def _parse_roles(user, role_bindings):
        user_roles = []
        for role in role_bindings['items']:
            if role['subjects'] is not None:
                for subject in role['subjects']:
                    if subject['name'] == user:
                        user_roles.append(role['roleRef']['name'])
                        break
        return user_roles

    @staticmethod
    def _parse_permissions(user_roles, all_roles):
        permissions = []
        for role in all_roles['items']:
            if role['metadata']['name'] in user_roles:
                permissions.append(role['rules'])
        return permissions

    @staticmethod
    def _parse_all_users_from_role_bindings(role_bindings):
        users = set()
        for role in role_bindings['items']:
            if role['subjects'] is not None:
                for subject in role['subjects']:
                    users.add(subject['name'])
        return users

    def _get_cluster_roles(self):
        return json.loads(subprocess.getoutput(f'{self._kubectl_path} -n {self._namespace} get clusterroles -o json'))

    def _get_namespace_roles(self):
        return json.loads(subprocess.getoutput(f'{self._kubectl_path} -n {self._namespace} get roles -o json'))

    def _get_cluster_role_bindings(self):
        return json.loads(subprocess.getoutput(f'{self._kubectl_path} -n {self._namespace} get clusterrolebindings -o json'))

    def _get_namespace_role_bindings(self):
        return json.loads(subprocess.getoutput(f'{self._kubectl_path} -n {self._namespace} get rolebindings -o json'))

    def get_permissions(self, user):
        user_roles = self.get_roles(user)

        cluster_roles = self._get_cluster_roles()
        permissions = self._parse_permissions(user_roles, cluster_roles)

        roles = self._get_namespace_roles()
        permissions += self._parse_permissions(user_roles, roles)

        return permissions

    def get_roles(self, user):
        cluster_role_bindings = self._get_cluster_role_bindings()
        user_roles = set(self._parse_roles(user, cluster_role_bindings))

        role_bindings = self._get_namespace_role_bindings()
        user_roles = user_roles.union(self._parse_roles(user, role_bindings))

        return user_roles

    @staticmethod
    def get_audited_permissions(user, audit_log_filepath):
        permissions = defaultdict(set)
        with open(audit_log_filepath, 'r') as f:
            audit_log = json.load(f)
            for entry in audit_log:
                if entry['protoPayload']['authenticationInfo']['principalEmail'] == user:
                    for permission in entry['protoPayload']['authorizationInfo']:
                        if 'granted' in permission:
                            permissions[permission['resource']].add(permission['permission'])
        return dict(permissions)

    def get_users(self):
        cluster_role_bindings = self._get_cluster_role_bindings()
        users = self._parse_all_users_from_role_bindings(cluster_role_bindings)

        roles = self._get_namespace_role_bindings()
        users = users.union(self._parse_all_users_from_role_bindings(roles))

        return users

    @staticmethod
    def get_least_privilege_role(user, audit_log_filepath):
        verb_to_resource = defaultdict(set)
        ROLE = {'apiVersion': 'rbac.authorization.k8s.io/v1',
                'kind': 'Role',
                'metadata': {
                    'name': f'octarine:{user}',
                    'namespace': f'{NAMESPACE}'},
                'rules': []
                }
        ROLE_BINDING = {'apiVersion': 'rbac.authorization.k8s.io/v1',
                        'kind': 'RoleBinding',
                        'metadata': {
                            'name': f'octarine:{user}',
                            'namespace': f'{NAMESPACE}'},
                        'roleRef': {'apiGroup': 'rbac.authorization.k8s.io',
                                    'kind': 'Role',
                                    'name': f'octarine:{user}'},
                        'subjects': [
                                {'apiGroup': 'rbac.authorization.k8s.io',
                                 'kind': 'User',
                                 'name': f'{user}'}
                            ]
                        }
        res = RBAC.get_audited_permissions(user, audit_log_filepath)
        for permission in res.values():
            for i in permission:
                if i.startswith('io.k8s.authorization.rbac.v1'):
                    resource, verb = i.split('.')[-2:]
                    verb_to_resource[verb].add(resource)
        rules = []
        for verb, resources in verb_to_resource.items():
            rules.append({'apiGroups': [''],
                          'resources': list(resources),
                          'verbs': [verb]})
        ROLE['rules'] = rules

        return ROLE, ROLE_BINDING

    def get_unused_permissions(self, user, audit_log_filepath):
        verbs = ["get", "list", "watch", "create", "update", "patch", "delete"]
        verb_to_resource = {k: set() for k in verbs}
        assigned_permissions = self.get_permissions(user)
        least_privilege_role, _ = self.get_least_privilege_role(user, audit_log_filepath)
        least_privilege_role = RBAC._get_verb_to_resource(least_privilege_role)
        for i in assigned_permissions:
            for perm in i:
                if 'apiGroups' in perm:
                    for verb in perm['verbs']:
                        if verb == '*':
                            for v in verbs:
                                if '*' in perm['resources']:
                                    verb_to_resource[v] = {'*'}
                                else:
                                    verb_to_resource[v] = verb_to_resource[v].union(perm['resources'])
                        else:
                            if '*' in perm['resources']:
                                verb_to_resource[verb] = {'*'}
                            else:
                                verb_to_resource[verb] = verb_to_resource[verb].union(perm['resources'])

        unused_permissions = copy.deepcopy(verb_to_resource)
        for verb, resources in verb_to_resource.items():
            unused_permissions[verb] = resources.difference(least_privilege_role[verb])
            if '*' in unused_permissions[verb]:
                unused_permissions[verb].remove('*')
                unused_permissions[verb] = unused_permissions[verb].union([f'*-{i}' for i in least_privilege_role[verb]])
        return unused_permissions


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='subcommands',
                                       dest='subparser_name')

    parser_get_permissions = subparsers.add_parser('get-permissions')
    parser_get_permissions.add_argument('user', type=str, help='user or service account')

    parser_get_roles = subparsers.add_parser('get-roles')
    parser_get_roles.add_argument('user', type=str, help='user or service account')

    parser_get_audited_permissions = subparsers.add_parser('get-audited-permissions')
    parser_get_audited_permissions.add_argument('user', type=str, help='user or service account')
    parser_get_audited_permissions.add_argument('log', type=str, help='path to audit log')

    subparsers.add_parser('get-users')

    parser_get_audited_permissions = subparsers.add_parser('get-least-privilege')
    parser_get_audited_permissions.add_argument('user', type=str, help='user or service account')
    parser_get_audited_permissions.add_argument('log', type=str, help='path to audit log')

    parser_get_audited_permissions = subparsers.add_parser('get-unused-permissions')
    parser_get_audited_permissions.add_argument('user', type=str, help='user or service account')
    parser_get_audited_permissions.add_argument('log', type=str, help='path to audit log')

    args = parser.parse_args()
    rbac = RBAC(NAMESPACE, KUBECTL_PATH)
    if args.subparser_name == 'get-roles':
        pprint.pprint(rbac.get_roles(args.user))
    elif args.subparser_name == 'get-permissions':
        pprint.pprint(rbac.get_permissions(args.user))
    elif args.subparser_name == 'get-audited-permissions':
        pprint.pprint(rbac.get_audited_permissions(args.user, args.log))
    elif args.subparser_name == 'get-users':
        pprint.pprint(rbac.get_users())
    elif args.subparser_name == 'get-least-privilege':
        role, role_binding = rbac.get_least_privilege_role(args.user, args.log)
        print(yaml.dump(role, default_flow_style=False))
        print('---')
        print(yaml.dump(role_binding, default_flow_style=False))
    elif args.subparser_name == 'get-unused-permissions':
        rbac.get_unused_permissions(args.user, args.log)


if __name__ == '__main__':
    main()
