/*++

Module Name:

    VirdidianFuzzer.c

Abstract:

    Kernel driver to make hypercalls, execute CPUID, read/write to MSRs as
    they can only be made from CPL0

Authors:

    Amardeep Chana

Environment:

    Kernel mode

--*/

#include "ViridianFuzzer.h"

CONST WCHAR     g_wzDeviceName[] = L"\\Device\\ViridianFuzzer";
CONST WCHAR     g_wzDosDeviceName[] = L"\\DosDevices\\ViridianFuzzer";
UNICODE_STRING  g_usDeviceName = { 0 };
UNICODE_STRING  g_usDeviceLink = { 0 };
PDEVICE_OBJECT  g_pDevObj = NULL;

//
// VIFU unload routine
//
VOID
DriverUnload (
    IN PDRIVER_OBJECT   pDriverObject
)
{
    UNREFERENCED_PARAMETER( pDriverObject );
    DbgPrint( "Driver unloading\n" );
    IoDeleteSymbolicLink( &g_usDeviceLink );
    IoDeleteDevice( g_pDevObj );
}

//
// IRP_MJ_xx not handled
//
NTSTATUS 
DispatchNotImplemented (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// Fill a VA with `content` 
//
VOID 
FillPage (
    IN OUT PCHAR    pInBuf,
    IN INT          bSize,
    IN UINT64       content8B 
)
{
    for( int i = 0; i < bSize / 8; i++ )
    {
        *((PUINT64)pInBuf + i) = content8B;
    }
    
}

//
// IOCTL handler. Transforms UM paramaters passed into valid kernel data, from 
// allocating pool memory to calculating PA's
//
NTSTATUS
DispatchIoctl (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
)
{
    PIO_STACK_LOCATION  pIsl = NULL;
    ULONG               ioctl = 0;
    NTSTATUS            status = STATUS_INTERNAL_ERROR;
    ULONG               bytesRet = 0;
    //
    // EAX, EBX, ECX, EDX
    //
    INT                 registers[4];

    UNREFERENCED_PARAMETER( DeviceObject );

    pIsl = IoGetCurrentIrpStackLocation( Irp );
    ioctl = pIsl->Parameters.DeviceIoControl.IoControlCode;

    switch( ioctl )
    {
        case IOCTL_HELLO:
            DbgPrint( "Hello World!\n" );
            if( pIsl->Parameters.DeviceIoControl.OutputBufferLength != 0 )
            {
                if( Irp->AssociatedIrp.SystemBuffer != NULL )
                {
                    *(ULONG*)(Irp->AssociatedIrp.SystemBuffer) = 0x41424344;
                    bytesRet = 4;
                    status = STATUS_SUCCESS;
                }
            }
            break;

        case IOCTL_CPUID_GET_VENDOR_ID:
            //
            // Return vendor ID signature (EBX,EDX,ECX)
            //
            __cpuid( registers, 0x00000000 );

            *(ULONG*)(Irp->AssociatedIrp.SystemBuffer) = registers[1];
            *((ULONG*)(Irp->AssociatedIrp.SystemBuffer) + 1) = registers[3];
            *((ULONG*)(Irp->AssociatedIrp.SystemBuffer) + 2) = registers[2];
            *((ULONG*)(Irp->AssociatedIrp.SystemBuffer) + 3) = registers[0];

            bytesRet = 16;
            status = STATUS_SUCCESS;
            break;

        case IOCTL_CPUID_GET_HV_ID:
            //
            // Check if a hypervisor is present, get it's ID, check if a root parition
            //

            //
            // Check ECX [31b], 1 indicates a Hypervisor is present
            //
            __cpuid( registers, 0x00000001 );
            if( (registers[2] >> 31) & 1 )
            {
                //
                // Check Hypervisor product name from CPUID leaf 0x40000000 (EBX,ECX,EDX) 
                //
                __cpuid( registers, 0x40000000 );
                if( strncmp( (CHAR*)(registers + 1), "Microsoft Hv", strlen( "Microsoft Hv" ) ) == 0 )
                {

                    //
                    // Check Hypervisor interface signature (EAX)
                    //
                    __cpuid( registers, 0x40000001 );
                    if( registers[0] == (ULONG)'1#vH' )
                    {

                        // TODO!!!

                        //
                        // Check CreatePartitions bit (EBX [1b]) from CPUID leaf 0x40000003 
                        //
                        __cpuid( registers, 0x40000003 );
                        if( registers[1] & 1 )
                        {
                            //
                            // HyperV root/parent parition
                            //
                            *(ULONG*)(Irp->AssociatedIrp.SystemBuffer) = 0x13370001;
                        }
                        else
                        {
                            //
                            // HyperV child parition
                            //
                            *(ULONG*)(Irp->AssociatedIrp.SystemBuffer) = 0x13370002;
                        }
                    }
                    else
                    {
                        // todo 40000001
                    }
                }
                else
                {
                    //
                    // Running on a non-Microsoft Hypervisor 
                    //
                    *(ULONG*)(Irp->AssociatedIrp.SystemBuffer) = 0x13370003;
                }
            }
            else
            {
                //
                // No Hypervisor detected, running on bare metal
                //
                *(ULONG*)(Irp->AssociatedIrp.SystemBuffer) = 0x13370004;
            }

            bytesRet = 4;
            status = STATUS_SUCCESS;
            break;

        case IOCTL_MSR_READ:
        {
            ULONG msr = *(PULONG)(Irp->AssociatedIrp.SystemBuffer);
            *(PULONG)(Irp->AssociatedIrp.SystemBuffer) = (ULONG)__readmsr( msr );

            bytesRet = 4;
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_CPUID:
        {
            INT cpuid = *(PULONG)(Irp->AssociatedIrp.SystemBuffer);
            PCPU_REG_32 pOutRegs = Irp->AssociatedIrp.SystemBuffer;

            __cpuid( (INT*)pOutRegs, cpuid );

            bytesRet = sizeof( CPU_REG_32 );
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_HYPERCALL:
        {
            HYPERCALL_RESULT_VALUE hvResult = { 0 };
            CPU_REG_64 inReg = { 0 };
            CPU_REG_64 outReg = { 0 };
            RtlCopyMemory( &inReg, 
                           Irp->AssociatedIrp.SystemBuffer, 
                           sizeof( CPU_REG_64 ) );

            //ULONG outBufLen = pIsl->Parameters.DeviceIoControl.OutputBufferLength;
            //PCHAR pOutBuf = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'VIFU');

            PCHAR pInBuf = ExAllocatePoolWithTag( NonPagedPool, 0x1000, 'VIFU' );
            //memset( pInBuf, 0x00, 0x1000 );
            RtlZeroMemory( pInBuf, 0x1000 );
            volatile PHYSICAL_ADDRESS realAddr = MmGetPhysicalAddress( pInBuf );

            //
            // Replace 0xIDENTIFIERs in each regs with GPA if required
            //
            for( int r = 0; r < (sizeof( CPU_REG_64 ) / sizeof( UINT64 )); r++ )
            {
                if( ((PUINT64)&inReg)[r] == USE_GPA_MEM_FILL )
                {
                    realAddr = MmGetPhysicalAddress( pInBuf );
                    //
                    // Fill GPA with ptr to itself
                    //
                    FillPage( pInBuf, 0x1000, realAddr.QuadPart );
                    //
                    // Set reg to GPA
                    //
                    ((PUINT64)&inReg)[r] = realAddr.QuadPart;
                }
                else if( ((PUINT64)&inReg)[r] == USE_GPA_MEM_NOFILL_0 )
                {
                    realAddr = MmGetPhysicalAddress( pInBuf );
                    FillPage( pInBuf, 0x1000, 0x00 );
                    ((PUINT64)&inReg)[r] = realAddr.QuadPart;
                }
                else if( ((PUINT64)&inReg)[r] == USE_GPA_MEM_NOFILL_1 )
                {
                    realAddr = MmGetPhysicalAddress( pInBuf );
                    FillPage( pInBuf, 0x1000, 0x01 );
                    ((PUINT64)&inReg)[r] = realAddr.QuadPart;
                }
                else if( ((PUINT64)&inReg)[r] == USE_GPA_MEM_BIT_RANGE_LOOP )
                {
                    //
                    // FIll in GPA with bits set e.g. 0y1 0y10 0y100 0y1000
                    //
                    realAddr = MmGetPhysicalAddress( pInBuf );
                    FillPage( pInBuf, 0x1000, inReg.rax );
                    ((PUINT64)&inReg)[r] = realAddr.QuadPart;
                }
            }

            //DbgBreakPoint();
            hvResult.result = VIFU_Hypercall( &inReg, &outReg );

            if( hvResult.result == HV_STATUS_SUCCESS )
            {
                RtlCopyMemory( Irp->AssociatedIrp.SystemBuffer, &outReg, sizeof( CPU_REG_64 ) );
                bytesRet = sizeof( CPU_REG_64 );
                status = STATUS_SUCCESS;
            }
            else
            {
                bytesRet = 0;
                status = VIFU_CREATE_ERR( hvResult.result, FACILITY_HYPERV );
            }

            ExFreePoolWithTag( pInBuf, 'VIFU' );
            //ExFreePoolWithTag( pOutBuf, 'VIFU' );
            break;
        }

        default:
            DbgPrint( "IOCTL not recognised\n" );
            bytesRet = 0;
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    Irp->IoStatus.Information = bytesRet;
    Irp->IoStatus.Status = status;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return status;
}

NTSTATUS 
DriverEntry (
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath
)
{
    NTSTATUS    status = STATUS_INTERNAL_ERROR;
    ULONG       i = 0;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("ViFu entry called\n");
    RtlInitUnicodeString(&g_usDeviceName, g_wzDeviceName);

    status = IoCreateDevice(DriverObject, 0, &g_usDeviceName, DEVICE_VIRIDIAN, 0, TRUE, &g_pDevObj);
    if (NT_SUCCESS(status))
    {
        RtlInitUnicodeString(&g_usDeviceLink, g_wzDosDeviceName);
        status = IoCreateSymbolicLink(&g_usDeviceLink, &g_usDeviceName);

        for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            DriverObject->MajorFunction[i] = DispatchNotImplemented;
        }
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
        DriverObject->DriverUnload = DriverUnload;
    }

    return status;
}
