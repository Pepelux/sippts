"""Shim setup file to allow for editable install."""

from setuptools import setup

scripts=[
  "bin/arpspoof",
  "bin/rtcpbleed",
  "bin/rtpbleed",
  "bin/rtpbleedflood",
  "bin/rtpbleedinject",
  "bin/sipdigestcrack",
  "bin/sipdigestleak",
  "bin/sippcapdump",
  "bin/sipenumerate",
  "bin/sipexten",
  "bin/sipflood",
  "bin/sipfuzzer",
  "bin/sipinvite",
  "bin/sipping",
  "bin/siprcrack",
  "bin/sipscan",
  "bin/sipsend",
  "bin/sipsniff",
  "bin/siptshark",
  "bin/wssend",
]

if __name__ == "__main__":
  setup(scripts=scripts)
