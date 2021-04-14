#pragma once

#include <wdm.h>

#define DEVICE_NAME L"\\Luks2"
#define DEBUG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

/* Driver routines */

DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE Luks2FltAddDevice;
DRIVER_DISPATCH   Luks2FltDispatchPassthrough;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
Luks2FltAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject
);

NTSTATUS
Luks2FltDispatchPassthrough(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

/* Type definitions */
typedef struct LUKS2FLT_DEVICE_EXTENSION {
    PDEVICE_OBJECT NextLowerDevice;
} LUKS2FLT_DEVICE_EXTENSION, * PLUKS2FLT_DEVICE_EXTENSION;