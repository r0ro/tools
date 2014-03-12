#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
from struct import *
import hashlib

if len(sys.argv) != 2:
  print("Usage " + sys.argv[0] + " input_file")
  sys.exit(1)

in_name = sys.argv[1]

def dumpHeader(f):
  # check for signature
  sig = f.read(3)
  if sig != b'FLV':
    print("Wrong signature got " + sig.encode('hex'))
    return False

  # check version
  version = unpack('B', f.read(1))[0]
  if version != 1:
    print("Wrong version got " + str(version))
    return False

  # get flags
  flags = unpack('B', f.read(1))[0]
  if flags & 0xFA:
    print("invalid flag got " + str(flags))
    return False

  # get header length
  hlen = unpack('!I', f.read(4))[0]
  if hlen != 9:
    print("invalid data offset got " + str(hlen))
    return False

  # get PreviousTagSize0
  s = unpack('!I', f.read(4))[0]
  if s != 0:
    print("invalid previous tag size 0 got " + str(s))
    return False

  print("========== FLV HEADER ==========")
  print("Version: " + str(version))
  print("TypeFlagsAudio: " + str(flags & 0x4))
  print("TypeFlagsVideo: " + str(flags & 0x1))
  print("DataOffset: " + str(hlen))
  print("================================")
  return True

lastTimestamp = -1

def dumpAudioHead(f):

  audioData = unpack('B', f.read(1))[0]
  fmt = audioData >> 4
  rate = 5.5 * 2**(audioData >> 2 & 0x03)
  size = audioData >> 1 & 0x01
  soundType = audioData & 0x01
  print("   Audio format: " + str(fmt) +
    " rate: " + str(rate) +
    " sample: " + ["8-bit","16-bit"][size] +
    " type: " + ["mono", "stereo"][soundType])

  if fmt != 10:
    return 1

  aacType = unpack('B', f.read(1))[0]
  print("   AAC type " + str(aacType))

  if aacType == 0:
    tags = f.read(2)
    print("    DATA: " + tags.encode('hex'))
    return 4

  return 2

def dumpTag(f):
  global lastTimestamp

  # get tag type
  type = unpack('B', f.read(1))[0]
  if type & 0xC0:
    print("Invalid tag type, first 2 bits should be null")
    return False
  filter = (type & 0x20) != 0
  tagType = type & 0x1F;

  # get data size
  (a,b,c) = unpack('BBB', f.read(3))
  dataSize = a << 16 | b << 8 | c

  # get timestamp
  (b,c,d,a) = unpack('BBBB', f.read(4))
  timestamp = a << 24 | b << 16 | c << 8 | d

  if timestamp < lastTimestamp:
    print("Timesamp goes backward: " + lastTimestamp + " vs " + timestamp)
    return False

  lastTimestamp = timestamp

  # get stream id
  (a,b,c) = unpack('BBB', f.read(3))
  if a | b | c:
    print("invalid stream id got " + str(a << 16 | b << 8 | c))
    return False

  # audio
  extraHeaderLen = 0
  if type == 8:
    extraHeaderLen = dumpAudioHead(f)

  # seek to end of data
  # f.seek(dataSize - extraHeaderLen, 1)

  # compute sha1 of payload
  m = hashlib.sha1()
  payload = f.read(dataSize - extraHeaderLen)
  m.update(payload)
  sha1 = m.hexdigest()

  print("> TAG type " + str(tagType) +
       " data size " + str(dataSize) +
       " timestamp " + str(timestamp) +
       " sha1: " + str(sha1))

  # read previous tag size
  prevLen = unpack('!I', f.read(4))[0]
  if (prevLen != 11 + dataSize):
    print("invalid prev length got " + str(prevLen) +
      " expected " + str(11 + dataSize))
    return False

  return True


with open(in_name, 'rb') as f:
  if not dumpHeader(f):
    print("Invalid FLV header", file=sys.stderr)
    sys.exit(1)
  i = 0
  while dumpTag(f):
    ++i

print("Done, processed " + str(i) + " tags")
