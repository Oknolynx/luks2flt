#pragma once

#include <wdm.h>

/* === Constants and macros === */
// the maximum number of device objects this driver may create
#define LUKS2FLT_MAX_DEVICES 32
// log everything as errors (for now) so that WinDbg must not be configured to show our messages
#define DEBUG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#define IRQL_ASSERT(Irql) ASSERT(KeGetCurrentIrql() == Irql)
// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes says the first value supplied
// to CTL_CODE "must match the value that is set in the DeviceType member of the driver's DEVICE_OBJECT". the function code
// is a random number between 0x800 and 0xFFF (as values below 0x800 are reserved for Microsoft).
#define IOCTL_LUKS2FLT_SET_LUKS2_INFO CTL_CODE(FILE_DEVICE_DISK, 0xc38, METHOD_BUFFERED, FILE_WRITE_DATA)

/* === Driver routine declarations === */
DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE Luks2FltAddDevice;
DRIVER_UNLOAD     Luks2FltUnload;
// actually this is the dispatch routine for all types, but this annotation makes the code analysis happy
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH   Luks2FltDispatchGeneric;
DRIVER_DISPATCH   Luks2FltDispatchPassthrough;
DRIVER_DISPATCH   Luks2FltDispatchCreateClose;
DRIVER_DISPATCH   Luks2FltDispatchDeviceControl;
DRIVER_DISPATCH   Luks2FltDispatchCleanup;
DRIVER_DISPATCH   Luks2FltDispatchPnp;

NTSTATUS
CompleteInvalidIrp(
    _In_ PIRP Irp
);

/* === Type definitions === */
// TODO
typedef struct LUKS2_VOLUME_INFO {
    UCHAR Key[64];
} LUKS2_VOLUME_INFO, * PLUKS2_VOLUME_INFO;

typedef struct LUKS2FLT_DEVICE_EXTENSION {
    PDEVICE_OBJECT NextLowerDevice;
    BOOLEAN IsLuks2Volume;
    LUKS2_VOLUME_INFO Luks2Info;
} LUKS2FLT_DEVICE_EXTENSION, * PLUKS2FLT_DEVICE_EXTENSION;