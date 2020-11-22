#!/usr/bin/env python3
import os
import re

from setuptools import setup, find_packages


version = None


def find(haystack, *needles):
    regexes = [(index, re.compile(r'^{}\s*=\s*[\'"]([^\'"]*)[\'"]$'.format(needle))) for index, needle in enumerate(needles)]
    values = ['' for needle in needles]

    for line in haystack:
        if len(regexes) == 0:
            break

        for rindex, (vindex, regex) in enumerate(regexes):
            match = regex.match(line)
            if match:
                values[vindex] = match.groups()[0]
                del regexes[rindex]
                break

    if len(needles) == 1:
        return values[0]
    else:
        return values


with open(os.path.join(os.path.dirname(__file__), 'mimameid', '__init__.py'), 'r') as mimameid:
    version = find(mimameid, '__version__')


setup(
    name='mimameid',
    version=version,
    description='an implementation of Mojang\'s Yggdrasil authentication',
    license='MIT',
    url='https://github.com/lilyinstarlight/mimameid',
    author='Lily Foster',
    author_email='lily@lily.flowers',
    install_requires=['fooster-web', 'fooster-db', 'httpx', 'rsa'],
    packages=find_packages(),
    package_data={'': ['html/*.*', 'res/*.*']},
    entry_points={'console_scripts': ['mimameid = mimameid.__main__:main']},
)
