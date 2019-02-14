import sys

if len(sys.argv) != 3:
    print "[-] Missing args: create.py <start> <end>"

start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)

for i in range(start, end+1):
    print '#define HvReserved000%x 0x000%x' % (i, i)
