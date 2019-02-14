#pragma once

#include <intrin.h>
#include <assert.h>
#include "HvStatusCodes.h"
#include "Msrs.h"
#include "Hypercalls.h"

#define DEVICE_VIRIDIAN             0x8041 

#define IOCTL_HELLO                 CTL_CODE(DEVICE_VIRIDIAN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_CPUID_GET_VENDOR_ID   CTL_CODE(DEVICE_VIRIDIAN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_CPUID_GET_HV_ID       CTL_CODE(DEVICE_VIRIDIAN, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_CPUID                 CTL_CODE(DEVICE_VIRIDIAN, 0x806, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_MSR_READ              CTL_CODE(DEVICE_VIRIDIAN, 0x804, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_HYPERCALL             CTL_CODE(DEVICE_VIRIDIAN, 0x805, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define DRIVER_WIN_OBJ              L"\\\\.\\ViridianFuzzer"

//
// Indicates to driver, to fill NonPagedPool page with ptrs to itself
//
#define USE_GPA_MEM_FILL            0x110000ff00

//
// Fill allocated kernel NonPagedPool page with 0's
//
#define USE_GPA_MEM_NOFILL_0        0x1100000000
#define USE_GPA_MEM_NOFILL_1        0x1100000001
#define USE_GPA_MEM_BIT_RANGE_LOOP  0x1100000002

typedef struct _CPU_REG_32
{
    UINT32 eax;
    UINT32 ebx;
    UINT32 ecx;
    UINT32 edx;
} CPU_REG_32, *PCPU_REG_32;

#define MSR_R   'MSRR'
#define MSR_W   'MSRW'

typedef struct UINT128
{
    UINT64 lower;
    UINT64 upper;
} VFUINT128, *PVFUINT128;

//
// Caution if editing this struct - the raw x64 asm relies on the sturct fields in this order
//
typedef struct _CPU_REG_64
{
    UINT64 rax;
    UINT64 rbx;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    VFUINT128 xmm0;
    VFUINT128 xmm1;
    VFUINT128 xmm2;
    VFUINT128 xmm3;
    VFUINT128 xmm4;
    VFUINT128 xmm5;
} CPU_REG_64, *PCPU_REG_64;

#pragma warning(disable:4214)
#pragma warning(disable:4201)
#pragma pack(push)
#pragma pack(push, 1)
//
// As defined in the MS TLFS - the Hypercall 64b value
// 
// 63:60|59:48        |47:44|43:32    |31:27|26:17             |16  |15:0
// -----+-------------+-----+---------+-----+------------------+----+---------
// Rsvd |Rep start idx|Rsvd |Rep count|Rsvd |Variable header sz|Fast|Call Code
// 4b   |12b          |4b   |12b      |5 b  |9b                |1b  |16b
//
typedef volatile union
{
        struct
        {
            UINT16 callCode             : 16;
            UINT16 fastCall             : 1;
            UINT16 variableHeaderSize   : 9;
            UINT16 rsvd1                : 5;
            UINT16 repCnt               : 12;
            UINT16 rsvd2                : 4;
            UINT16 repStartIdx          : 12;
            UINT16 rsvd3                : 4;
        };
    UINT64 AsUINT64;
} HV_X64_HYPERCALL_INPUT, *PHV_X64_HYPERCALL_INPUT;
C_ASSERT(sizeof(HV_X64_HYPERCALL_INPUT) == 8);

//
// TLFS Hypercall Result Value returned from hypercall
//
typedef volatile union
{
    struct
    {
        UINT16 result       : 16;
        UINT16 rsvd1        : 16;
        UINT32 repComplete  : 12;
        UINT32 rsvd2        : 20;
    };
    UINT64 AsUINT64;
} HYPERCALL_RESULT_VALUE;
C_ASSERT(sizeof(HYPERCALL_RESULT_VALUE) == 8);

#pragma pack(pop)
#pragma warning(default:4201) 
#pragma warning(disable:4214)

//
// Virdian Fuzzer errors (are just custom NTSTATUS errs)
//
// If FACILITY_VIFU is set in C the error occured in the driver itself,
// else if FACILITY_HYPERVISOR is set the HV_STATUS err is in code
//
// NTSTAUS error format
//  3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
//  1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
// +---+-+-------------------------+-------------------------------+
// |Sev|C|       Facility          |               Code            |
// +---+-+-------------------------+-------------------------------+
// 
#define VIFU_STATUS             UINT32
#define NON_NT                  1
#define FACILITY_VIFU           0x1F1
#define FACILITY_HYPERV         0X1F2
#define VIFU_CREATE_ERR(err, facility)  ( (STATUS_SEVERITY_ERROR << 30) |   \
                                        (NON_NT << 29) |                    \
                                        (facility << 16) |                  \
                                        err )
#define IS_VIFU_ERR(err)        ((err >> 29) & 1)
#define VIFU_ERR_FACILITY(err)  (err >> 16 & 0x1FFF)
#define VIFU_ERR_CODE(err)      (err & 0xFFFF)

//
// Format for passing data into driver for Hypercall IOCTL
//
/*typedef struct _HYPERCALL_SYSTEMBUF
{
    UINT64 callcode;
    CPU_REG_64 regs;
} HYPERCALL_SYSTEMBUF, *PHYPERCALL_SYSTEMBUF;*/

//
// HyperV
//
typedef UINT16 HV_STATUS;
typedef UINT64 HV_PARTITION_ID;
typedef UINT64 HV_GPA;
typedef UINT64 HV_ADDRESS_SPACE_ID;
typedef HV_PARTITION_ID *PHV_PARTITION_ID;
typedef UINT64 HV_NANO100_TIME;
typedef HV_NANO100_TIME *PHV_NANO100_TIME;
typedef UINT64 HV_PARTITION_PROPERTY;
typedef HV_PARTITION_PROPERTY *PHV_PARTITION_PROPERTY;
typedef UINT8 HV_INTERCEPT_ACCESS_TYPE_MASK;
typedef UINT32 HV_VP_INDEX;
typedef UINT32 HV_INTERRUPT_VECTOR;
typedef HV_INTERRUPT_VECTOR *PHV_INTERRUPT_VECTOR;
typedef UINT16 HV_X64_IO_PORT;

/*
typedef union _HV_PARTITION_PRIVILEGE_MASK
{
    UINT64 AsUINT64;
    struct
    {
        //
        // Access to virtual MSRs
        //
        UINT64  AccessVpRunTimeMsr : 1;
        UINT64  AccessPartitionReferenceCounter : 1;
        UINT64  AccessSynicMsrs : 1;
        UINT64  AccessSyntheticTimerMsrs : 1;
        UINT64  AccessApicMsrs : 1;
        UINT64  AccessHypercallMsrs : 1;
        UINT64  AccessVpIndex : 1;
        UINT64  Rsvd1 : 25;

        //
        // Access to hypercalls
        //
        UINT64  CreatePartitions : 1;
        UINT64  AccessPartitionId : 1;
        UINT64  AccessMemoryPool : 1;
        UINT64  AdjustMessageBuffers : 1;
        UINT64  PostMessages : 1;
        UINT64  SignalEvents : 1;
        UINT64  CreatePort : 1;
        UINT64  ConnectPort : 1;
        UINT64  AccessStats : 1;
        UINT64  IteratePhysicalHardware : 1;
        UINT64  ExposeHyperthreads : 1;
        UINT64  Debugging : 1;
        UINT64  CpuPowerManagement : 1;
        UINT64  Rsvd2 : 19;
    };

} HV_PARTITION_PRIVILEGE_MASK, *PHV_PARTITION_PRIVILEGE_MASK;
*/
