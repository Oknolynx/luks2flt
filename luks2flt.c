#include "luks2flt.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

/* Global variables */
PDEVICE_OBJECT Luks2Device;

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
/*++
Routine Description:
    Create the device object and perform all other driver initialization.
Arguments:
    DriverObject - the driver object created by the system.
    RegistryPath - path to the driver's registry key.
Return Value:
    STATUS_SUCCESS.
--*/
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DEBUG("luks2flt!DriverEntry called\n");

    DriverObject->DriverUnload = Luks2FltUnload;
    // this driver doesn't have a StartIo() routine because it passes IRPs down to the next driver
    // after applying small changes. See also
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/writing-a-startio-routine
    DriverObject->DriverStartIo = NULL;
    DriverObject->DriverExtension->AddDevice = Luks2FltAddDevice;
    DriverObject->MajorFunction[IRP_MJ_CREATE] =
    DriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE] =
    DriverObject->MajorFunction[IRP_MJ_CLOSE] =
    DriverObject->MajorFunction[IRP_MJ_READ] =
    DriverObject->MajorFunction[IRP_MJ_WRITE] =
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] =
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] =
    DriverObject->MajorFunction[IRP_MJ_QUERY_EA] =
    DriverObject->MajorFunction[IRP_MJ_SET_EA] =
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] =
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] =
    DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION] =
    DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] =
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] =
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] =
    DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] =
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] =
    DriverObject->MajorFunction[IRP_MJ_CREATE_MAILSLOT] =
    DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY] =
    DriverObject->MajorFunction[IRP_MJ_SET_SECURITY] =
    DriverObject->MajorFunction[IRP_MJ_POWER] =
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] =
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CHANGE] =
    DriverObject->MajorFunction[IRP_MJ_QUERY_QUOTA] =
    DriverObject->MajorFunction[IRP_MJ_SET_QUOTA] =
    DriverObject->MajorFunction[IRP_MJ_PNP] = Luks2FltDispatchPassthrough;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
Luks2FltAddDevice(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT DeviceObject
)
/*++
Routine Description:
    Creates a new device object and attaches it to the given device object's device stack.
Arguments:
    DriverObject - the driver's driver object.
    DeviceObject - a physical device object created by a lower-level driver.
Return Value:
    If IoCreateDevice() fails, its error code is returned. If IoAttachDeviceToDeviceStack() fails, STATUS_DEVICE_NOT_CONNECTED
    is returned. Else STATUS_SUCCESS is returned.
--*/
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(DeviceObject);

    DEBUG("luks2flt!AddDevice called\n");

    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    PDEVICE_OBJECT NextLowerDevice;

    RtlInitUnicodeString(&DeviceName, DEVICE_NAME_PREFIX);
    Status = IoCreateDevice(
        DriverObject,
        sizeof(LUKS2FLT_DEVICE_EXTENSION),
        &DeviceName,
        FILE_DEVICE_DISK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &Luks2Device
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    NextLowerDevice = IoAttachDeviceToDeviceStack(
        Luks2Device,
        DeviceObject
    );

    if (NextLowerDevice == NULL) {
        IoDeleteDevice(Luks2Device);
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    RtlZeroMemory(Luks2Device->DeviceExtension, sizeof(LUKS2FLT_DEVICE_EXTENSION));
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)Luks2Device->DeviceExtension;
    DevExt->NextLowerDevice = NextLowerDevice;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchPassthrough(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Default dispatch method that passes the received IRP on to the next driver in the stack, untouched.
Arguments:
    DeviceObject - the device object for the target device.
    IRP - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    DEBUG("luks2!DispatchPassthrough called with major function=0x%02x\n", stack->MajorFunction);

    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DevExt->NextLowerDevice, Irp);
}

_Use_decl_annotations_
VOID
Luks2FltUnload(
    PDRIVER_OBJECT DriverObject
)
/*++
Routine Description:
    Cleanup and free all allocated memory.
Arguments:
    DriverObject - the driver object created by the system.
Return Value:
    None.
--*/
{
    UNREFERENCED_PARAMETER(DriverObject);
    // nothing to free yet
}