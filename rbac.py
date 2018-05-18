import os
import yaml
import json
import pprint
import argparse
import subprocess
from collections import defaultdict


NAMESPACE = os.environ.get('KUBECTL_PLUGINS_CURRENT_NAMESPACE')
KUBECTL_PATH = os.environ.get('KUBECTL_PLUGINS_CALLER')


def parse_all_users_from_role_bindings(role_bindings):
    users = set()
    for role in role_bindings['items']:
        if role['subjects'] is not None:
            for subject in role['subjects']:
                users.add(subject['name'])
    return users


def parse_roles(user, role_bindings):
    user_roles = []
    for role in role_bindings['items']:
        if role['subjects'] is not None:
            for subject in role['subjects']:
                if subject['name'] == user:
                    user_roles.append(role['roleRef']['name'])
                    break
    return user_roles


def parse_permissions(user_roles, all_roles):
    permissions = []
    for role in all_roles['items']:
        if role['metadata']['name'] in user_roles:
            permissions.append(role['rules'])
    return permissions


def get_permissions(user):
    user_roles = get_roles(user)

    cluster_roles = json.loads(subprocess.getoutput(f'{KUBECTL_PATH} -n {NAMESPACE} get clusterroles -o json'))
    permissions = parse_permissions(user_roles, cluster_roles)

    roles = json.loads(subprocess.getoutput(f'{KUBECTL_PATH} -n {NAMESPACE} get roles -o json'))
    permissions += parse_permissions(user_roles, roles)

    return permissions


def get_roles(user):
    cluster_role_bindings = json.loads(subprocess.getoutput(f'{KUBECTL_PATH} -n {NAMESPACE} get clusterrolebindings -o json'))
    user_roles = parse_roles(user, cluster_role_bindings)

    role_bindings = json.loads(subprocess.getoutput(f'{KUBECTL_PATH} -n {NAMESPACE} get rolebindings -o json'))
    user_roles += parse_roles(user, role_bindings)

    return user_roles


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


def get_users():
    cluster_role_bindings = json.loads(subprocess.getoutput(f'{KUBECTL_PATH} -n {NAMESPACE} get clusterrolebindings -o json'))
    users = parse_all_users_from_role_bindings(cluster_role_bindings)

    roles = json.loads(subprocess.getoutput(f'{KUBECTL_PATH} -n {NAMESPACE} get rolebindings -o json'))
    users.union(parse_all_users_from_role_bindings(roles))

    return users


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
    res = get_audited_permissions(user, audit_log_filepath)
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

    args = parser.parse_args()
    if args.subparser_name == 'get-roles':
        pprint.pprint(get_roles(args.user))
    elif args.subparser_name == 'get-permissions':
        pprint.pprint(get_permissions(args.user))
    elif args.subparser_name == 'get-audited-permissions':
        pprint.pprint(get_audited_permissions(args.user, args.log))
    elif args.subparser_name == 'get-users':
        pprint.pprint(get_users())
    elif args.subparser_name == 'get-least-privilege':
        role, role_binding = get_least_privilege_role(args.user, args.log)
        print(yaml.dump(role, default_flow_style=False))
        print('---')
        print(yaml.dump(role_binding, default_flow_style=False))


if __name__ == '__main__':
    main()
