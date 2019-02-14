# -*- coding: utf-8 -*-
# Description:
# - Find Hypercall Dispatch Table
# - Extract all Hypercalls inlcuding undocumented after end
# - Fix up IDB - renaming func_ptr to hypercall name and setting stuct field sizes
# - Create .h with all call codes in table
# Assuming base of 0x0

import sys
import idaapi
from collections import namedtuple

# Apply to IDB 
APPLY_TO_IDB = True
hypercalls_from_pdf_path = 'HypercallsOnlyFromPdf.h'
hypercalls_undoc_path = 'Hypercalls.h'

HypercallDispatchFormat = namedtuple('HypercallDispatchFormat',
                                     ['func_ptr',
                                      'call_code',
                                      'is_rep_call',
                                      'input_size_1',
                                      'input_size_2',
                                      'output_size_1',
                                      'output_size_2',
                                      'unkw'])

HypercallDefine = namedtuple('HypercallDefine',
                             ['define',
                              'hypercall_name',
                              'call_code'])

# Hypercall table alway seems to appear in segment "CONST"
hypercall_dispatch_table = idaapi.get_segm_by_name("CONST").startEA
print '[+] Hypercall Dispatch Table: ' + hex(hypercall_dispatch_table)

# Find +X segment
segX_start = 0
segX_end = 0
for ea in idautils.Segments():
    seg = idaapi.getseg(ea)
    if seg and (seg.perm & idaapi.SEGPERM_EXEC):
        SigmName = idc.SegName(ea)
        print '[+] Segments with +X permission: ' + SigmName
        segX_start = seg.startEA
        segX_end = seg.endEA

# Loop through hypercall table
hypercalls = []
valid_hypercall = True
addr = hypercall_dispatch_table
while valid_hypercall:
    func_ptr = idaapi.get_qword(addr)
    # Set struct field sizes in IDA in the HypercallDispatchFormat format
    if APPLY_TO_IDB:
        MakeQword(addr)
    addr += 8
    
    call_code = idaapi.get_word(addr)
    if APPLY_TO_IDB:
        MakeWord(addr)
    addr += 2
    
    is_rep_call = idaapi.get_word(addr)
    if APPLY_TO_IDB:
        MakeWord(addr)
    addr += 2
    
    input_size_1 = idaapi.get_word(addr)
    if APPLY_TO_IDB:
        MakeWord(addr)
    addr += 2
    
    input_size_2 = idaapi.get_word(addr)
    if APPLY_TO_IDB:
        MakeWord(addr)
    addr += 2
    
    output_size_1 = idaapi.get_word(addr)
    if APPLY_TO_IDB:
        MakeWord(addr)
    addr += 2
    
    output_size_2 = idaapi.get_word(addr)
    if APPLY_TO_IDB:
        MakeWord(addr)
    addr += 2
    
    unkw = idaapi.get_dword(addr)
    if APPLY_TO_IDB:
        MakeDword(addr)
    addr += 4    

    # A valid hypercall struct will contain a valid func_ptr
    if func_ptr >= segX_start and func_ptr <= segX_end:
        hypercalls.append(HypercallDispatchFormat(func_ptr=func_ptr, call_code=call_code, is_rep_call=is_rep_call, input_size_1=input_size_1, input_size_2=input_size_2, output_size_1=output_size_1, output_size_2=output_size_2, unkw=unkw))
    else:
        valid_hypercall = False
        break

# Get hypercall names from C header Hypercalls.h
hypercall_format_size = 24
hypercall_define = []
# Open Hypercalls.h
with open(hypercalls_from_pdf_path, 'rb') as hypercalls_pdf_h:
    for line in hypercalls_pdf_h:
        # Find #define per line
        if re.match('\\s*#define.*', line):
            # Get rid of new lines at end
            line = re.sub('\r\n|\r|\n', '', line)
            # Get rid of indent for some #defines
            line = re.sub('\\s*#define', '#define', line)
            if len(line.split(' ')) != 3:
                print '[-] Something went wrong with ' + line
            hypercall_define.append(HypercallDefine(*line.split(' ')))
           
# Link up hypercall name from .h file with func_ptrs found from this .idb
for hypercall in hypercalls:
    # Use call_code as index into dispatch table
    func_ptr_hc = idc.get_qword(hypercall_dispatch_table + (hypercall_format_size * hypercall.call_code))
  
    for define in hypercall_define:
        # Use call_code to get hypercall name from header #defines
        define_callcode = int(define.call_code, 16)
        if define_callcode == hypercall.call_code:
            #print define.hypercall_name, hex(hypercall.call_code)

            # Fix IDB
            if APPLY_TO_IDB:
                MakeNameEx(func_ptr_hc, define.hypercall_name, SN_NOWARN)
                MakeCode(func_ptr_hc)
                MakeFunction(func_ptr_hc)

# Create C .h file of all hypercalls
with open(hypercalls_undoc_path, 'w+') as hypercalls_h:
    addr = hypercall_dispatch_table
    valid_hypercall = True
    hypercalls_h.write('//\n// Auto-generated file from extract_vmcall_handler_table.py\n//\n')
    hypercalls_h.write('typedef struct { const CHAR *name; UINT16 callcode; UINT16 isRep; UINT16 inputSize; UINT16 outputSize; } HYPERCALL_ENTRY;\n\n')
    hypercalls_h.write('HYPERCALL_ENTRY HypercallEntries[] = {\n')
        
    while valid_hypercall:
        func_ptr = idaapi.get_qword(addr)
        addr += 8
        call_code = idaapi.get_word(addr)
        addr += 2
        is_rep_call = idaapi.get_word(addr)
        addr += 2        
        input_size_1 = idaapi.get_word(addr)
        addr += 2
        input_size_2 = idaapi.get_word(addr)
        addr += 2
        output_size_1 = idaapi.get_word(addr)
        addr += 2
        output_size_2 = idaapi.get_word(addr)
        addr += 2
        unkw = idaapi.get_dword(addr)
        addr += 4
        
        if func_ptr >= segX_start and func_ptr <= segX_end:
            func_name = GetFunctionName(func_ptr)
			# Get rid of python 'L' -_-
            call_code_str = hex(call_code)[:-1]
            func_name = re.sub('Reserved....', 'Reserved' + call_code_str, func_name)
            hypercalls_h.write('{"' + func_name + '", ' + call_code_str + ', ' + str(is_rep_call) + ', ' + str(input_size_1) + ', ' + str(output_size_1) +'},\n')
        else:
            valid_hypercall = False
            break      
    hypercalls_h.write('};\n')
