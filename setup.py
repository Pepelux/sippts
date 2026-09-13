"""Shim setup file to allow for editable install."""

from setuptools import setup

scripts=[
  "bin/sippts",
  "bin/sippts-gui"
]

if __name__ == "__main__":
  setup(scripts=scripts,
    name='SIPPTS',
      author='Jose Luis Verdeguer aka Pepelux',
      version='4.1',
      install_requires=[
        'netifaces',
        'requests',
        'IPy',
        'scapy',
        'pyshark',
        'websocket-client',
        'rel'
      ],
      # 'extra_requires' is not a setuptools option and was silently ignored,
      # so these were never declared anywhere: install them with .[full]
      extras_require={
        'full': [
          'cursor',
          'asterisk-ami'
        ]
      },
    include_package_data=True,
    package_data={'sippts': ['data/cve.csv']}
    )
