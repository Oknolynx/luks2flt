#pragma once

#include <wdm.h>

/* === Constants and macros === */
// the maximum number of device objects this driver may create
#define LUKS2FLT_MAX_DEVICES 32
// log everything as errors (for now) so that WinDbg must not be configured to show our messages
#define DEBUG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#define IRQL_ASSERT(Irql) ASSERT(KeGetCurrentIrql() == Irql)

/* === Driver routine declarations === */
DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE Luks2FltAddDevice;
DRIVER_UNLOAD     Luks2FltUnload;
// not the only dispatch type, but as the dispatch routine organization will soon change and this
// annotation makes the code analysis happy it should suffice for now
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH   Luks2FltDispatchPassthrough;

/* === Type definitions === */
typedef struct LUKS2FLT_DEVICE_EXTENSION {
    PDEVICE_OBJECT NextLowerDevice;
} LUKS2FLT_DEVICE_EXTENSION, * PLUKS2FLT_DEVICE_EXTENSION;