# Author: Amardeep S C
# 
# To use just copy and paste a table (e.g. return codes) from the 
# "Hypervisor Top Level Functional Specification.pdf" Appendix
# into the "hvstatuscodes_pdf.txt" file and this script will search
# and make a C header with the return codes
# 
# extract_ret_codes_from_pdf.py ../hvstatuscodes_pdf.txt ViridianFuzzer/HvStatusCodes.h
# extract_ret_codes_from_pdf.py ../msrs.txt ViridianFuzzer/Msrs.h
#

import sys
import re

if len(sys.argv) != 3:
	print "[-] Missing args: extract_ret_codes_from_pdf.py <FilePathToCopiedText> <OutputHeader>"
	
header_path = sys.argv[1]
output_path = sys.argv[2]
reserved_cnt = 0;
	
with open(output_path, 'w+') as file_header:
	file_header.write('//\n// Auto-generated header file from extract_ret_codes_from_pdf.py\n//\n')
	with open(header_path, "rb") as file_hvstatus_code:
		for line in file_hvstatus_code:
			# If 0x found at start of regex, then extract that line (status) and next line (name)
			if re.match("0x", line):
				status_code = line.rstrip("\r\n")
				line = next(file_hvstatus_code)
				status_name = line.rstrip("\r\n").rstrip(".")
				
				# If "Reserved" found, append number at the end to avoid macro redefinition errs in C
				if status_name == "Reserved":
					status_name = status_name + str(reserved_cnt)
					reserved_cnt += 1
					
				file_header.write("#define " + status_name + " " + status_code + "\n") 
