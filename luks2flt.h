#pragma once

#include <wdm.h>

#define DEVICE_NAME_PREFIX L"\\Luks2"
// log everything as errors (for now) so that WinDbg must not be configured to show our messages
#define DEBUG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

/* Driver routines */
DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE Luks2FltAddDevice;
DRIVER_DISPATCH   Luks2FltDispatchPassthrough;
DRIVER_UNLOAD     Luks2FltUnload;

/* Type definitions */
typedef struct LUKS2FLT_DEVICE_EXTENSION {
    PDEVICE_OBJECT NextLowerDevice;
} LUKS2FLT_DEVICE_EXTENSION, * PLUKS2FLT_DEVICE_EXTENSION;