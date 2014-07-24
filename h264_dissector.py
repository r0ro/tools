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

def printNalu(f, start, end):
  # seek to start
  f.seek(start, 0)

  # get header info
  b = unpack('B', f.read(1))[0]
  if (b & 0x80):
    print("WARN: forbidden_zero_bit is set !")
  nal_ref_idc = (b >> 5) & 0x3
  nal_unit_type = b & 0x1F

  # seek to start
  f.seek(start, 0)

  # compute sha1 of payload (without head)
  m = hashlib.sha1()
  payloadLen = end - start
  payload = f.read(payloadLen)
  m.update(payload)
  sha1 = m.hexdigest()

  print ("[NALU] type: " + str(nal_unit_type)
         + " ref_idc: " + str(nal_ref_idc)
         + " len: " + str(payloadLen)
         + " sha1: " + str(sha1))

  # print("   START: " + payload[0:32].encode('hex'))
  # if payloadLen > 32:
  #   print("   END:   " + payload[payloadLen-31:].encode('hex'))

def extractNalu(f):
  head = f.read(3)
  if not head:
    return False

  # look for nalu start code
  a,b,c = unpack('BBB', head)
  while a != 0 or b != 0 or c != 1:
    # move forward
    a = b
    b = c
    h = f.read(1)
    if not h:
      return False
    c = unpack('B', h)[0]

  # found nalu start
  start = f.tell()

  # look for nalu end
  head = f.read(3)
  if not head:
    return False

  a,b,c = unpack('BBB', head)
  while a != 0 or b != 0 or (c != 0 and c != 1):
    # move forward
    a = b
    b = c
    h = f.read(1)
    if not h:
      return False
    c = unpack('B', h)[0]

  # found nalu end
  end = f.tell() - 3

  printNalu(f, start, end)

  # got back to nalu end
  f.seek(end, 0)
  return True

with open(in_name, 'rb') as f:
  try:
    i = 0
    while extractNalu(f):
      i += 1
  except EOFError:
    print("unexpected end of file")


print("Done, processed " + str(i) + " NALU")
