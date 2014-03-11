#!/usr/bin/python

import sys

if len(sys.argv) != 3:
	print "Usage m2ts_to_mpeg input_file output_file"
	sys.exit(1)

in_name = sys.argv[1]
out_name = sys.argv[2]

with open(in_name, 'rb') as f:
	with open(out_name, 'wb') as o:
		while f.read(4): # discard timestamp
			bytes = f.read(188)
			if not bytes:
				break
			o.write(bytes)


print "Done"
