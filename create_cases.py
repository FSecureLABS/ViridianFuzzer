import sys

if len(sys.argv) != 3:
    print "[-] Missing args: create.py <0xstart> <0xend>"

start = int(sys.argv[1], 10)
end = int(sys.argv[2], 10)

newline = 1
for i in range(start, end):
    sys.stdout.write('case %d: ' % (i))
    
    if newline % 6 == 0:
        sys.stdout.write('\r\n')    
        newline = 0
    newline += 1
