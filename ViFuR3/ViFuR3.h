#pragma once

#include <Windows.h>
#include <time.h>  
#include "../ViridianFuzzer/ViridianFuzzerTypes.h"

//
// Config vars for share (in our case its parent)
//
#define UNC_LOG_PATH        L"\\\\DESKTOP-6IIUE90\\Violet_SHARE"
#define UNC_LOG_FILEPATH    L"\\\\DESKTOP-6IIUE90\\Violet_SHARE\\VIFU_LOG.txt"
#define UNC_LOG_FUZZCMD     L"\\\\DESKTOP-6IIUE90\\Violet_SHARE\\fuzz_logger.txt"
#define AUTO_START_FILE     L"\\\\DESKTOP-6IIUE90\\Violet_SHARE\\autoStart.txt"
//
//
//

#define STR_FMT_DATETIME    "\r\n[ %02d/%02d/%04d %02d:%02d:%02d ]\r\n"

#define PRINT_CPU_REG(eax, ebx, ecx, edx)   \
    printf("EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n", eax, ebx, ecx, edx);

#define PRINT_CPU_REG_64(rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11)                    \
    printf("    rax 0x%016llx rbx 0x%016llx rcx 0x%016llx rdx 0x%016llx rsi 0x%016llx\n",   \
    rax, rbx, rcx, rdx, rsi);                                                               \
    printf("    rdi 0x%016llx r8  0x%016llx r9  0x%016llx r10 0x%016llx r11 0x%016llx\n",   \
    rdi, r8, r9, r10, r11);

#define WRITE_REGS_TO_LOG_FILE(rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11)                  \
    WriteToLogFile(g_hLogfile, "    rax 0x%016llx rbx 0x%016llx rcx 0x%016llx rdx 0x%016llx rsi 0x%016llx\n"\
    "    rdi 0x%016llx r8  0x%016llx r9  0x%016llx r10 0x%016llx r11 0x%016llx\n",              \
    rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11);
