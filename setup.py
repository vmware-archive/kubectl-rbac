#!/usr/bin/env python

from setuptools import setup
from codecs import open


def readme():
    with open('README.md', 'r', 'utf-8') as f:
        return f.read()


setup(name='kubectl-rbac',
      version='1.0',
      description='Kubectl RBAC Plugin',
      long_description=readme(),
      author='Octarine',
      author_email='info@octarinesec.com',
      url='https://github.com/octarinesec/kubectl-rbac',
      packages=['kubectl_rbac'],
      entry_points = {
          'console_scripts': [
              'kubectl-rbac = kubectl_rbac.rbac:main'
              ]
      },
      classifiers=['Intended Audience :: Developers',
                   'Natural Language :: English',
                   'License :: OSI Approved :: MIT License',
                   'Programming Language :: Python :: 3.6']
     )
