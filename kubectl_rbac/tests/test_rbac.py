import json
import pprint
import unittest
from unittest.mock import MagicMock
from kubectl_rbac.rbac import RBAC
from kubectl_rbac.tests.audited_permissions import TEST_AUDITED_PERMISSIONS


class TestKubeRBAC(unittest.TestCase):
    TEST_USER = 'user@octarinesec.com'
    TEST_ROLE = 'octarine-role:user@octarinesec.com'
    TEST_PERMISSIONS = [[{'apiGroups': [''],
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
    TEST_LEAST_PRIVILEGE_ROLE = {'apiVersion': 'rbac.authorization.k8s.io/v1',
                                 'kind': 'Role',
                                 'metadata': {'name': 'octarine:user@octarinesec.com', 'namespace': 'None'},
                                 'rules': [{'apiGroups': [''],
                                            'resources': ['roles', 'clusterrolebindings', 'rolebindings', 'clusterroles'],
                                            'verbs': ['list']},
                                           {'apiGroups': [''],
                                            'resources': ['clusterrolebindings', 'clusterroles'],
                                            'verbs': ['get']}
                                           ]
                                 }

    def __init__(self, *args, **kwargs):
        super(TestKubeRBAC, self).__init__(*args, **kwargs)
        with open('./rolebindings.json', 'r') as f:
            self.TEST_ROLE_BINDINGS = json.load(f)
        with open('./roles.json', 'r') as f:
            self.TEST_ROLES = json.load(f)
        with open('./audit_log.json', 'r') as f:
            self.TEST_AUDIT_LOG = json.load(f)

    @staticmethod
    def _get_verb_to_resource(role):
        verbs = ["get", "list", "watch", "create", "update", "patch", "delete"]
        verb_to_resource = {k: set() for k in verbs}
        for rule in role['rules']:
            for verb in rule['verbs']:
                verb_to_resource[verb] = verb_to_resource[verb].union(rule['resources'])
        return verb_to_resource

    @staticmethod
    def _compare_roles(role1, role2):
        verb_to_resource1 = TestKubeRBAC._get_verb_to_resource(role1)
        verb_to_resource2 = TestKubeRBAC._get_verb_to_resource(role2)
        return verb_to_resource1 == verb_to_resource2

    def test_parse_roles(self):
        roles = RBAC._parse_roles('user@octarinesec.com', self.TEST_ROLE_BINDINGS)
        self.assertEqual(roles, [self.TEST_ROLE])

    def test_parse_permissions(self):
        permissions = RBAC._parse_permissions([self.TEST_ROLE], self.TEST_ROLES)
        self.assertEqual(json.dumps(permissions), json.dumps(self.TEST_PERMISSIONS))

    def test_parse_all_users_from_role_bindings(self):
        users = RBAC._parse_all_users_from_role_bindings(self.TEST_ROLE_BINDINGS)
        self.assertEqual(users, {self.TEST_USER})

    def test_get_roles(self):
        rbac = RBAC('default', None)
        rbac._get_cluster_role_bindings = MagicMock(return_value=self.TEST_ROLE_BINDINGS)
        rbac._get_namespace_role_bindings = MagicMock(return_value=self.TEST_ROLE_BINDINGS)
        self.assertEqual(rbac.get_roles(self.TEST_USER), {'octarine-role:user@octarinesec.com'})

    def test_get_permissions(self):
        rbac = RBAC('default', None)
        rbac._get_namespace_roles = MagicMock(return_value=self.TEST_ROLES)
        rbac._get_cluster_roles = MagicMock(return_value={'items': []})
        rbac._get_namespace_role_bindings = MagicMock(return_value=self.TEST_ROLE_BINDINGS)
        rbac._get_cluster_role_bindings = MagicMock(return_value={'items': []})
        self.assertEqual(json.dumps(rbac.get_permissions(self.TEST_USER)), json.dumps(self.TEST_PERMISSIONS))

    def test_get_users(self):
        rbac = RBAC('default', None)
        rbac._get_namespace_role_bindings = MagicMock(return_value=self.TEST_ROLE_BINDINGS)
        rbac._get_cluster_role_bindings = MagicMock(return_value={'items': []})
        self.assertEqual(rbac.get_users(), {self.TEST_USER})

    def test_get_audited_permissions(self):
        audited_permissions = RBAC.get_audited_permissions(self.TEST_USER, './audit_log.json')
        self.assertEqual(audited_permissions, TEST_AUDITED_PERMISSIONS)

    def test_get_least_privilege_role(self):
        role, rolebinding = RBAC.get_least_privilege_role(self.TEST_USER, './audit_log.json')
        self.assertTrue(TestKubeRBAC._compare_roles(role, self.TEST_LEAST_PRIVILEGE_ROLE))


if __name__ == '__main__':
    unittest.main()
