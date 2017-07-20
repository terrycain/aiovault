#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = ''.join(history_file.readlines()[1:])


requirements = [
    'aiohttp',
    'python-dateutil'
]

setup_requirements = [
    'pytest-runner'
]

test_requirements = [
    'pytest',
    'Sphinx',
    'sphinx-autodoc-typehints',
    'pytest-asyncio',
    'pytest-aiohttp',
    'requests',
    'coverage'
]

setup(
    name='aiovault',
    version='0.2.0',
    description="Vault asyncio",
    long_description=readme + '\n\n' + history,
    author="Terry Cain",
    author_email='terry@terrys-home.co.uk',
    url='https://github.com/terrycain/aiovault',
    packages=find_packages(include=['aiovault']),
    include_package_data=True,
    install_requires=requirements,
    license="GNU General Public License v3",
    zip_safe=False,
    keywords='aiovault',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    setup_requires=setup_requirements,
)
