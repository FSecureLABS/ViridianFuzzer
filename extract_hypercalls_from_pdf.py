import sys
import re
import PyPDF2
from collections import namedtuple

# if len(sys.argv) != 3:
#    print "[-] Missing args: extract_ret_codes_from_pdf.py <FilePathToCopiedText> <OutputHeader>"

# header_path = sys.argv[1]
# output_path = sys.argv[2]
# reserved_cnt = 0;

#header_path = '../hypercalls_pdf.txt'
output_path = 'HypercallsOnlyFromPdf.txt'

pdf_file = open('Hypervisor Top Level Functional Specification v5.0b.pdf', 'rb')
pdf2_obj = PyPDF2.PdfFileReader(pdf_file)
max_page = pdf2_obj.getNumPages()


# Find 'Appendix - Hypercall Code Reference' string in PDF
page_hypercall = 0
for i in range(max_page - 1 -40, 0, -1):
    page = pdf2_obj.getPage(i)
    page_content = page.extractText()
    if re.search(ur'.*Hypercall Code Reference.*', page_content, re.UNICODE):
        page_hypercall = i
        break

HypercallRowFormat = namedtuple('HypercallRowFormat',
                                ['call_code', 'rep_call', 'fast_call', 'hypercall', 'caller', 'privelege_req', 'end'])
hypercalls = []
appendix_found = 0

for i in range(page_hypercall, max_page - 1):
    table_row = ''
    page = pdf2_obj.getPage(i)
    page_content = page.extractText()

    if re.search('Appendix', page_content):
        appendix_found += 1
        if appendix_found > 1:
            break

    # Extract lines from PDF table by matching on '0x...' regex, indicating start of a row
    rows_str = []
    possible_entry = page_content.split('\n0x')
    for entry in possible_entry:
        entry = '0x' + entry
        if re.match('.*0x[0-9a-fA-F]{4}.*', entry):
            rows_str.append(entry)

    # Fix cases where call code has ranges, i.e. string "0005 thr\nough 0077" in it by combining current entry and next
    for i, entry in enumerate(rows_str):
        if re.search('0x....\n \nthr', entry, re.DOTALL):
            rows_str[i] += rows_str[i+1]
            del rows_str[i+1]
        # Edge case for txt speach "thru" .. good one Microsoft!
        elif re.search('0x.... \nthr', entry, re.DOTALL):
            rows_str[i] += rows_str[i + 1]
            del rows_str[i + 1]

    # Extract data from row - consistent format (except for call code ranges)
    for row in rows_str:
        splitted_fields = row.split('\n ')
        if len(splitted_fields) == 7:
            hypercalls.append(HypercallRowFormat(*splitted_fields))
        else:
            # Check if 'thr\nough' or 'thru' in callcode fields split accross 0,1,2
            if re.search('thr.*', splitted_fields[1]) and len(splitted_fields) == 9:
                splitted_fields[0] = splitted_fields[0] + splitted_fields[1] + splitted_fields[2]
                del splitted_fields[1:3]
                hypercalls.append(HypercallRowFormat(*splitted_fields))
            else:
                # Unrecognized hypercall - requires manual fixing up
                hypercalls.append(HypercallRowFormat('BAD FORMATTING', '', '', '', '', '', ''))

# Set the rep_call and fast_call to a boolean
# And check for errors in caller from PDF
for i, hypercall in enumerate(hypercalls):
    if hypercall.rep_call != '':
        hypercalls[i] = hypercalls[i]._replace(rep_call='TRUE')
    if hypercall.fast_call != '':
        hypercalls[i] = hypercalls[i]._replace(fast_call='TRUE')

    caller = hypercall.caller.replace('\n', '')
    if ('Error' in caller) or ('--' in caller):
        hypercalls[i] = hypercalls[i]._replace(caller='[ERROR_CALLER]')
    else:
        hypercalls[i] = hypercalls[i]._replace(caller=hypercall.caller.replace(' ', ''))


# No longer using as header - as my other script directly extracts data from hypervisor binary
# but this is useful to associate named hypercalls with callcode and caller 
with open(output_path, 'w+') as file_header:
    file_header.write('//\n')
    file_header.write('// Auto-generated file from extract_hypercalls_from_pdf.py\n')
    file_header.write('// * Manually inspect all hypercalls - PDF table extraction is a bit hacky\n')
    file_header.write('// * Hypercalls with call ranges/bad formats simply are not listed here\n')
    file_header.write('// ** Any "    #define" are manually added in and gend from create_hvreserved_defines.py\n')
    file_header.write('// ** "Deprecate" and "Reserved" manually renamed *\n')

    file_header.write('//\n')

    for hypercall in hypercalls:
        call_code = hypercall.call_code.replace('\n', '').replace('thru', '-').replace('through', '-')
        hypercall_name = hypercall.hypercall.replace('\n', '')
        caller = hypercall.caller.replace('\n', '')
        if len(call_code) == 6 and re.match('0x[0-9a-fA-F]{4}', call_code):
            file_header.write('#define ' + hypercall_name + ' ' + call_code + ' ' + caller + '\n')
        else:
            file_header.write('[MANUALLY_FIX] ' + call_code + ' ' + hypercall_name + ' ' + caller + '\n')

