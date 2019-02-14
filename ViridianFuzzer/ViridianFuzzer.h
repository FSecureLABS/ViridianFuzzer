#pragma once
//
// Need to use ntddk.h over wdm.h for MmGetPhysicalAddress()
//
// #include <wdm.h>
#include <ntddk.h>
#include "ViridianFuzzerTypes.h"

//
// X64 ASM proc because there is no intrinsics for VMCALL
// Note: args passed in as (x64 calling convention) are 
// directly passed to vmcall
//
#pragma optimize("", off)
__declspec(noinline)
HV_STATUS
__fastcall
VIFU_Hypercall
(
    IN  PCPU_REG_64 regsIn,
    OUT PCPU_REG_64 regsOut
);
#pragma optimize("", on)
