import os
import sys
import json
import pprint
import subprocess
from collections import defaultdict


NAMESPACE = os.environ.get('KUBECTL_PLUGINS_CURRENT_NAMESPACE')
KUBECTL_PATH = os.environ.get('KUBECTL_PLUGINS_CALLER')


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


def main(subcommand, user, *args):
    if subcommand == 'get-permissions':
        pprint.pprint(get_permissions(user))
    elif subcommand == 'get-roles':
        pprint.pprint(get_roles(user))
    elif subcommand == 'get-audited-permissions':
        if len(args) == 0:
            print('json audit log file must be provided')
            exit(1)
        pprint.pprint(get_audited_permissions(user, args[0]))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('user/service-account must be provided')
        exit(1)
    main(sys.argv[1], sys.argv[2], *sys.argv[3:])
