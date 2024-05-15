"""Shim setup file to allow for editable install."""

from setuptools import setup

scripts=[
  "bin/sippts"
]

if __name__ == "__main__":
  setup(scripts=scripts,
        include_package_data=True,
        package_data={'sippts': ['data/cve.csv']}
        )
