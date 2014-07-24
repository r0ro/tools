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

def dumpAAC(data, offset, size):
  aacType = unpack('B', data[offset])[0]
  offset += 1
  print("    > [AAC] Type: " + str(aacType) + "\t|" + ["AAC HEADER", "AAC PAYLOAD"][aacType])


audioFormatsStr = [
  "Linear PCM, platform endian",
  "ADPCM",
  "MP3",
  "Linear PCM, little endian",
  "Nellymoser 16-kHz mono",
  "Nellymoser 8-kHz mono",
  "Nellymoser",
  "G.711 A-law logarithmic PCM",
  "G.711 mu-law logarithmic PCM",
  "reserved",
  "AAC",
  "Speex",
  "MP3 8-Khz",
  "Device-specific sound"
]

def dumpAudioPayload(data):
  offset = 0
  audioData = unpack('B', data[offset])[0]
  fmt = audioData >> 4
  rate = 5.5 * 2**(audioData >> 2 & 0x03)
  size = audioData >> 1 & 0x01
  soundType = audioData & 0x01
  offset += 1

  print("  > [AUDIO] format: " + audioFormatsStr[fmt] + " | rate: " + str(rate)
        + " | sample: " + ["8-bit","16-bit"][size]
        + " type: " + ["mono", "stereo"][soundType])

  if fmt == 10:
    # dump AAC
    return dumpAAC(data, 1, size)

  return True

def dumpNALU(data, offset, size):
  origOffset = offset

  # ignore padding
  while (unpack('B', data[offset+size-1])[0] == 0):
    #print("remove padding 0 " + str(unpack('B', data[offset+size-1])) + " SZ: " + str(size))
    size -= 1

  totLen = size

  m = hashlib.sha1()
  m.update(data[offset:offset+size])
  sha1 = m.hexdigest()

  a = unpack('B', data[offset])[0]
  offset += 1
  if a & 0x80:
    print("Invalid forbidden_zero_bit")
    return False
  nal_ref_idc = a >> 5
  nal_unit_type = a & 0x1F

  print("    > [NALU] Type: " + str(nal_unit_type) + "\t| LEN " + str(totLen) + "\t| SHA1: " + sha1)
  # print("       START: " + data[origOffset:origOffset+32].encode('hex'))
  # if totLen > 32:
  #   print("       END:   " + data[origOffset+size-31:origOffset+size].encode('hex'))
  return True

def dumpVideoPayload(data):
  # read head
  offset = 0
  a = unpack('B', data[offset])[0]
  frameType = a >> 4;
  codecID = a & 0x0F;
  offset += 1
  info = "  > [VIDEO] frameType: " + str(frameType) + " | CodecID: " + str(codecID) + " | len: " + str(len(data))
  if codecID == 7:
    AVCPacketType = unpack('B', data[offset])[0]
    offset += 1
    (a, b, c) = unpack('BBB', data[offset:offset+3])
    compTime = a << 16 | b << 8 | c
    offset += 3
    if AVCPacketType == 0:
      info += "\t|SEQ HEADER"
    elif AVCPacketType == 1:
      info += "\t| AVC NALU"
    elif AVCPacketType == 2:
      info += "\t|END OF SEQ"
    info += "\t| COMP: " + str(compTime)

  print(info)
  totLen = len(data)

  # print AVC Nalu
  if codecID == 7 and AVCPacketType == 1:
    while offset < totLen - 4:
      # extract nalu size
      naluSize = unpack('!I', data[offset:offset+4])[0]
      offset += 4
      if not dumpNALU(data, offset, naluSize):
        return False
      offset += naluSize

  return True

def dumpTag(f):
  global lastTimestamp
  hStr = ""

  d = f.read(1)
  if not d:
    return False

  # get tag type
  type = unpack('B', d)[0]
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
    print("Timesamp goes backward: " + str(lastTimestamp) + " vs " + str(timestamp))

  # get stream id
  (a,b,c) = unpack('BBB', f.read(3))
  if a | b | c:
    print("invalid stream id got " + str(a << 16 | b << 8 | c))
    return False

  # read payload
  payload = f.read(dataSize)

  # compute sha1 of payload
  m = hashlib.sha1()
  m.update(payload)
  sha1 = m.hexdigest()

  tagTypeSrt = "unknown"

  if tagType == 9:
    tagTypeSrt = "Video"
  elif tagType == 8:
    tagTypeSrt = "Audio"
  elif tagType == 18:
    tagTypeSrt = "ScriptData"

  print("> TAG type " + str(tagType) + " (" + tagTypeSrt + ")" +
         " data size " + str(dataSize) +
         " timestamp " + str(timestamp) +
         " time diff " + str(timestamp - lastTimestamp) +
         " sha1: " + str(sha1))

  # read previous tag size
  prevLen = unpack('!I', f.read(4))[0]
  if (prevLen != 11 + dataSize):
    print("invalid prev length got " + str(prevLen) +
      " expected " + str(11 + dataSize))
    return False

  lastTimestamp = timestamp

  # dump payload
  if tagType == 9:
    # video
    if not dumpVideoPayload(payload):
      return False
  elif tagType == 8:
    if not dumpAudioPayload(payload):
      return False

  return True

with open(in_name, 'rb') as f:
  try:
    if not dumpHeader(f):
      print("Invalid FLV header", file=sys.stderr)
      sys.exit(1)
    i = 0
    while dumpTag(f):
      i += 1
  except EOFError:
    print("unexpected end of file")


print("Done, processed " + str(i) + " tags")
