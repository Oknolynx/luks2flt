#include "luks2flt.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

/* Global variables */
PDEVICE_OBJECT Luks2Device;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
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

    DriverObject->DriverExtension->AddDevice = Luks2FltAddDevice;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_READ] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_QUERY_EA] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_SET_EA] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_CREATE_MAILSLOT] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_SET_SECURITY] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_POWER] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CHANGE] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_QUERY_QUOTA] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_SET_QUOTA] = Luks2FltDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_PNP] = Luks2FltDispatchPassthrough;

    // TODO (?)
    // DriverObject->FastIoDispatch = &Luks2FastIoDispatch;

    return STATUS_SUCCESS;
}

NTSTATUS
Luks2FltAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject
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

    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
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