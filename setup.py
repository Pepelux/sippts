"""Shim setup file to allow for editable install."""

from setuptools import setup

scripts=[
  "bin/sippts"
]

if __name__ == "__main__":
  setup(scripts=scripts,
    name='SIPPTS',
      author='Jose Luis Verdeguer - Pepelux',
      version='4.0',
      install_requires=[     
        'netifaces',
        'requests',
        'IPy',
        'scapy',
        'pyshark',
        'websocket-client',
        'rel',
        'cursor'
      ],
      extra_requires=[
        'ArpSpoof'
      ],
    include_package_data=True,
    package_data={'sippts': ['data/cve.csv']}
    )
