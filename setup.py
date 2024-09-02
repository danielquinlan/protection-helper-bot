#!/usr/bin/env python3

import glob

from setuptools import setup, find_packages

scripts = [script for script in glob.glob("scripts/*") if not script.endswith("~")]

setup(
    name="protection-helper-bot",
    description="Protection Helper Bot scripts",
    version="0.1",
    packages=find_packages(),
    install_requires=[],
    scripts=scripts,
    package_data={},
    python_requires='>=3.10',
)
