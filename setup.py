"""Shim setup file to allow for editable install."""

import os
import shutil

from setuptools import setup

scripts=[
  "bin/sippts",
  "bin/sippts-gui"
]

AQUI = os.path.dirname(os.path.abspath(__file__))
FICHERO_VERSION = os.path.join(AQUI, "version")


def copiar_version():
  """
  Put a copy inside the package so an installed sippts can read it: the
  'version' file of the root is not part of the package.
  """
  destino = os.path.join(AQUI, "src", "sippts", "data", "version.txt")

  try:
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    shutil.copyfile(FICHERO_VERSION, destino)
  except OSError:
    pass


copiar_version()

if __name__ == "__main__":
  setup(scripts=scripts,
    name='SIPPTS',
      author='Jose Luis Verdeguer aka Pepelux',
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
    package_data={'sippts': ['data/cve.csv', 'data/version.txt']}
    )
