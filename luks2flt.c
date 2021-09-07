#include "luks2flt.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

/* === Global variables === */
// The device objects this driver has created.
PDEVICE_OBJECT gDeviceObjects[LUKS2FLT_MAX_DEVICES];

// The number of device objects this driver has created.
UINT16 gDeviceObjectCount;

// A lookaside sist used for (de)allocations of LUKS2FLT_READ_CONTEXTs. Must be aligned to 16 bytes.
__declspec(align(16)) LOOKASIDE_LIST_EX gReadContextList;

// A lookaside sist used for (de)allocations of LUKS2FLT_DEVICE_CONTROL_CONTEXTs. Must be aligned to 16 bytes.
__declspec(align(16)) LOOKASIDE_LIST_EX gDeviceControlContextList;

/* a FAST_MUTEX must be 8-byte aligned on 64-bit platforms, see
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinitializefastmutex
 */
// Mutex for accessing gDeviceObjects.
__declspec(align(8)) FAST_MUTEX gDeviceObjectsMutex;

// Mutex for accessing gDeviceObjectCount.
__declspec(align(8)) FAST_MUTEX gDeviceObjectCountMutex;

/* === Driver routine implementations === */
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

    IRQL_ASSERT(PASSIVE_LEVEL);

    // === Initialize driver routines ===
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
    DriverObject->MajorFunction[IRP_MJ_PNP] = Luks2FltDispatchGeneric;

    // === Initialize global variables ===
    RtlZeroMemory(gDeviceObjects, sizeof(gDeviceObjects));
    gDeviceObjectCount = 0;
    ExInitializeFastMutex(&gDeviceObjectsMutex);
    ExInitializeFastMutex(&gDeviceObjectCountMutex);
    ExInitializeLookasideListEx(
        &gReadContextList,
        NULL,
        NULL,
        // the context allocated from this list is used in the read completion routine,
        // which may be called at IRQL = DISPATCH_LEVEL, therefore we need non-paged memory
        NonPagedPoolNx,
        0,
        sizeof(LUKS2FLT_READ_CONTEXT),
        READCTX_TAG,
        0
    );
    ExInitializeLookasideListEx(
        &gDeviceControlContextList,
        NULL,
        NULL,
        // see above
        NonPagedPoolNx,
        0,
        sizeof(LUKS2FLT_DEVICE_CONTROL_CONTEXT),
        DEVCTLCTX_TAG,
        0
    );

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
    Create a new device object and attach it to the given device object's device stack.
Arguments:
    DriverObject - the driver's driver object.
    DeviceObject - a physical device object created by a lower-level driver.
Return Value:
    If IoCreateDevice() fails, its error code is returned. If the driver has already created LUKS2FLT_MAX_DEVICES device objects,
    IoAttachDeviceToDeviceStack() fails or the lower device in the device stack has neither one of the DO_DIRECT_IO and DO_BUFFERED_IO
    flags set, STATUS_DRIVER_INTERNAL_ERROR is returned. Else STATUS_SUCCESS is returned.
--*/
{
    DEBUG("luks2flt!AddDevice called\n");

    IRQL_ASSERT(PASSIVE_LEVEL);

    NTSTATUS Status;
    PDEVICE_OBJECT NextLowerDevice;
    UINT16 DeviceObjectNumber;

    /* === Get number of new device === */
    ExAcquireFastMutex(&gDeviceObjectCountMutex);
    if (gDeviceObjectCount < LUKS2FLT_MAX_DEVICES - 1) {
        DeviceObjectNumber = gDeviceObjectCount++;
    } else {
        DEBUG("luks2flt!AddDevice: ERROR - gDeviceObjectCount already equal to LUKS2FLT_MAX_DEVICES!\n");
        ExReleaseFastMutex(&gDeviceObjectCountMutex);
        return STATUS_DRIVER_INTERNAL_ERROR;
    }
    ExReleaseFastMutex(&gDeviceObjectCountMutex);

    /* === Create new device === */
    ExAcquireFastMutex(&gDeviceObjectsMutex);
    // we are now running at IRQL = APC_LEVEL until we release the mutex (see
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/fast-mutexes-and-guarded-mutexes).
    // all following function calls can run at that IRQL, except for IoDetachDevice(), which is why
    // we ensure it is called after releasing the mutex

    // "WDM filter and function drivers do not name their device objects." (from
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice)
    Status = IoCreateDevice(
        DriverObject,
        sizeof(LUKS2FLT_DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_DISK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        gDeviceObjects + DeviceObjectNumber
    );

    if (!NT_SUCCESS(Status)) {
        ExReleaseFastMutex(&gDeviceObjectsMutex);
        return Status;
    }

    DEBUG("luks2flt!AddDevice: DEBUG - created device object at %p\n", gDeviceObjects[DeviceObjectNumber]);

    /* === Attach device === */
    NextLowerDevice = IoAttachDeviceToDeviceStack(
        gDeviceObjects[DeviceObjectNumber],
        DeviceObject
    );

    if (NextLowerDevice == NULL) {
        DEBUG("luks2flt!AddDevice: ERROR - IoAttachDeviceToDeviceStack() returned NULL!\n");
        IoDeleteDevice(gDeviceObjects[DeviceObjectNumber]);
        ExReleaseFastMutex(&gDeviceObjectsMutex);
        return STATUS_DRIVER_INTERNAL_ERROR;
    }

    DEBUG("luks2flt!AddDevice: DEBUG - attached to NextLowerDevice=%p\n", NextLowerDevice);

    /* === Set up device flags === */
    // see https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/initializing-a-device-object
    gDeviceObjects[DeviceObjectNumber]->Flags &= ~DO_DEVICE_INITIALIZING;
    if (NextLowerDevice->Flags & DO_DIRECT_IO) {
        gDeviceObjects[DeviceObjectNumber]->Flags |= DO_DIRECT_IO;
        DEBUG("luks2flt!AddDevice: DEBUG - matching lower device and setting DO_DIRECT_IO flag\n");
    }
    else if (NextLowerDevice->Flags & DO_BUFFERED_IO) {
        gDeviceObjects[DeviceObjectNumber]->Flags |= DO_BUFFERED_IO;
        DEBUG("luks2flt!AddDevice: DEBUG - matching lower device and setting DO_BUFFERED_IO flag\n");
    }
    else {
        DEBUG("luks2flt!AddDevice: ERROR - NextLowerDevice has neither DO_DIRECT_IO nor DO_BUFFERED_IO set!\n");
        IoDeleteDevice(gDeviceObjects[DeviceObjectNumber]);
        ExReleaseFastMutex(&gDeviceObjectsMutex);
        // IoDetachDevice must run at IRQL = PASSIVE_LEVEL and therefore needs to be called after releasing the mutex
        IoDetachDevice(NextLowerDevice);
        return STATUS_DRIVER_INTERNAL_ERROR;
    }

    /* === Initialize device extension === */
    RtlZeroMemory(gDeviceObjects[DeviceObjectNumber]->DeviceExtension, sizeof(LUKS2FLT_DEVICE_EXTENSION));
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)gDeviceObjects[DeviceObjectNumber]->DeviceExtension;
    DevExt->NextLowerDevice = NextLowerDevice;
    DevExt->IsLuks2Volume = FALSE;

    ExReleaseFastMutex(&gDeviceObjectsMutex);

    return STATUS_SUCCESS;
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

    DEBUG("luks2flt!Unload called\n");

    IRQL_ASSERT(PASSIVE_LEVEL);

    ExDeleteLookasideListEx(&gReadContextList);
    ExDeleteLookasideListEx(&gDeviceControlContextList);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchGeneric(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Default dispatch routine that either calls Luks2FltDispatchPassthrough(), the appropriate routine for LUKS2 volumes, or
    fails the IRP.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    Either the return value of Luks2FltDispatchPassthrough(), the return value of the appropriate LUKS2 dispatch routine, or
    STATUS_INVALID_DEVICE_REQUEST.
--*/
{
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    // fast path for non-LUKS2 volumes if not a DeviceIoControl IRP with code IOCTL_LUKS2FLT_SET_LUKS2_INFO
    // and not a PnP IRP with code IRP_MN_REMOVE_DEVICE (as DispatchPnp() already implements the logic for
    // handling these requests we also use it for non-LUKS2 volumes)
    if (!DevExt->IsLuks2Volume &&
        ((Stack->MajorFunction != IRP_MJ_DEVICE_CONTROL) || (Stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_DISK_SET_LUKS2_INFO)) &&
        ((Stack->MajorFunction != IRP_MJ_PNP) || (Stack->MinorFunction != IRP_MN_REMOVE_DEVICE)))
        return Luks2FltDispatchPassthrough(DeviceObject, Irp);

    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        return Luks2FltDispatchCreateClose(DeviceObject, Irp);
    case IRP_MJ_READ:
        return Luks2FltDispatchRead(DeviceObject, Irp);
    /*
    case IRP_MJ_WRITE:
        return Luks2FltDispatchWrite(DeviceObject, Irp);
    */
    case IRP_MJ_DEVICE_CONTROL:
        return Luks2FltDispatchDeviceControl(DeviceObject, Irp);
    case IRP_MJ_CLEANUP:
        return Luks2FltDispatchCleanup(DeviceObject, Irp);
    case IRP_MJ_POWER:
        return Luks2FltDispatchPower(DeviceObject, Irp);
    case IRP_MJ_PNP:
        return Luks2FltDispatchPnp(DeviceObject, Irp);
    /*
    case IRP_MJ_QUERY_INFORMATION:
    case IRP_MJ_QUERY_EA:
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
    case IRP_MJ_QUERY_SECURITY:
    case IRP_MJ_QUERY_QUOTA:
    */
    case IRP_MJ_FLUSH_BUFFERS:
    case IRP_MJ_SHUTDOWN:
        return Luks2FltDispatchPassthrough(DeviceObject, Irp);
    }

    return FailIrp(Irp, STATUS_INVALID_DEVICE_REQUEST);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchPassthrough(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine that passes the received IRP on to the next driver in the stack, untouched.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    // this is ok because we don't modify the IRP and don't register a completion routine. if we did
    // either of that, we'd have to use IoCopyCurrentIrpStackLocationToNext()
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DevExt->NextLowerDevice, Irp);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine for IRP_MJ_CREATE and IRP_MJ_CLOSE. Just calls DispatchPassthrough().
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    // Regarding IRP_MJ_CREATE:
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create says:
    // "If the target device object is the filter driver's control device object, the filter driver's dispatch routine must complete the IRP
    // and return an appropriate NTSTATUS value, after setting Irp->IoStatus.Status and Irp->IoStatus.Information to appropriate values.
    //
    // Otherwise, the filter driver should perform any needed processingand, depending on the nature of the filter, either complete the IRP
    // or pass it down to the next - lower driver on the stack."
    //
    // However, I'm not sure what they mean by "the target device" -- the DeviceObject parameter is always a device object created by this driver
    // and the device object in the IRP's stack location for this driver seems to always be the same object. As this driver does not support
    // opening its devices, we just pass the request to the next lower driver -- either the request was not meant for us and we should pass it on
    // or it was meant for us and the drivers below will notice that and fail the request.

    // Regarding IRP_MJ_CLOSE:
    // As we don't do anything for IRP_MJ_CREATE, we also just pass on IRP_MJ_CLOSE requests.

    // Regarding both:
    // Decompiling the FveFilterCreate() and FveFilterClose() routines of the fvevol driver shows that (apart from some cases that are guarded
    // by checking values in the device extension and are thus out of my reach to understand) they also just pass create and close requests
    // down the stack. Therefore this should be fine.

    return Luks2FltDispatchPassthrough(DeviceObject, Irp);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchRead(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine for IRP_MJ_READ. Registers a completion routine for decrypting the read data
    and passes the request down the device stack.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    // don't do anything if zero bytes shall be read
    if (Stack->Parameters.Read.Length > 0) {
        PLUKS2FLT_READ_CONTEXT Context = ExAllocateFromLookasideListEx(&gReadContextList);
        if (Context == NULL) {
            DEBUG("luks2flt!DispatchRead - ERROR: ExAllocateFromLookasideListEx returned NULL!\n");
            return FailIrp(Irp, STATUS_INSUFFICIENT_RESOURCES);
        }

        Context->OrigByteOffset = Stack->Parameters.Read.ByteOffset.QuadPart;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        Stack = IoGetNextIrpStackLocation(Irp);

        // Move ByteOffset by the offset of the segment
        Stack->Parameters.Read.ByteOffset.QuadPart += DevExt->Luks2Info.FirstSegmentSector * DevExt->Luks2Info.SectorSize;

        IoSetCompletionRoutine(
            Irp,
            Luks2FltCompleteRead,
            Context,
            TRUE,
            FALSE,
            FALSE
        );
    } else {
        IoSkipCurrentIrpStackLocation(Irp);
    }

    return IoCallDriver(DevExt->NextLowerDevice, Irp);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchWrite(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine for IRP_MJ_WRITE. Encrypts the data before sending the request to the next lower
    driver in the device stack.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    // don't do anything if zero bytes shall be read
    if (Stack->Parameters.Write.Length > 0) {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        Stack = IoGetNextIrpStackLocation(Irp);

        PUINT8 Buffer = MmGetSystemAddressForMdlSafe(
            Irp->MdlAddress,
            NormalPagePriority | MdlMappingNoExecute
        );

        EncryptWriteBuffer(
            Buffer,
            &DevExt->Luks2Info,
            &DevExt->Luks2Crypto,
            Stack->Parameters.Write.ByteOffset.QuadPart,
            Stack->Parameters.Write.Length
        );

        // Move ByteOffset by the offset of the segment
        Stack->Parameters.Write.ByteOffset.QuadPart += DevExt->Luks2Info.FirstSegmentSector * DevExt->Luks2Info.SectorSize;
    } else {
        IoSkipCurrentIrpStackLocation(Irp);
    }

    return IoCallDriver(DevExt->NextLowerDevice, Irp);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine for IRP_MJ_DEVICE_CONTROL. The action depends on the IOCTL of the request:
    * IOCTL_DISK_SET_LUKS2_INFO requests are completed successfully.
    * IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_GET_PARTITION_INFO(_EX) and IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS requests have
      a completion routine registered.
    * Requests with a completion routine as well as a list of (supposedly) non-destructive IOCTLs are passed on to the next lower driver.
    * All other requests are marked as invalid and completed.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    STATUS_SUCCESS for IOCTL_LUKS2FLT_SET_LUKS2_INFO if the input buffer is big enough (else STATUS_INVALID_DEVICE_REQUEST),
    STATUS_INVALID_DEVICE_REQUEST for IOCTL_DISK_SET_PARTITION_INFO(_EX), the same as the returned value of the call to
    the driver of the next lower device for all other IOCTLs.
--*/
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_DISK_SET_LUKS2_INFO: {
        DEBUG("luks2flt!DispatchDeviceControl: DEBUG - got IOCTL_LUKS2FLT_SET_LUKS2_INFO\n");

        // the IOCTL uses buffered IO, therefore Buffer is a system buffer. this means it doesn't need to be locked and can be accessed directly
        PUINT8 Buffer = (PUINT8)Irp->AssociatedIrp.SystemBuffer;

        if (Buffer[0] && (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(LUKS2_VOLUME_INFO) + 1)) {
            DEBUG("luks2flt!DispatchDeviceControl: ERROR - InputBufferLength too small (less than sizeof(LUKS2_VOLUME_INFO) + 1)!\n");
            return FailIrp(Irp, STATUS_BUFFER_TOO_SMALL);
        }

        // normalize value, just in case
        DevExt->IsLuks2Volume = Buffer[0] ? TRUE : FALSE;

        DEBUG("luks2flt!DispatchDeviceControl: DEBUG - set IsLuks2Volume to %s\n", DevExt->IsLuks2Volume ? "TRUE" : "FALSE");

        if (DevExt->IsLuks2Volume) {
            PLUKS2_VOLUME_INFO nDevExt = (PLUKS2_VOLUME_INFO)(Buffer + 1);
            if ((nDevExt->EncVariant != AES_128_XTS) && (nDevExt->EncVariant != AES_256_XTS)) {
                DEBUG("luks2flt!DispatchDeviceControl: DEBUG - message contains invalid encryption variant");
                return FailIrp(Irp, STATUS_INVALID_PARAMETER);
            }

            RtlCopyMemory(
                &DevExt->Luks2Info,
                nDevExt,
                sizeof(LUKS2_VOLUME_INFO)
            );

            switch (DevExt->Luks2Info.EncVariant) {
            case AES_128_XTS:
                 Aes128XtsInit(&DevExt->Luks2Crypto.Xts, DevExt->Luks2Info.Key);
                 DevExt->Luks2Crypto.Encrypt = Aes128XtsEncrypt;
                 DevExt->Luks2Crypto.Decrypt = Aes128XtsDecrypt;
                break;
            case AES_256_XTS:
            default: // we already checked the validity of the parameter
                Aes256XtsInit(&DevExt->Luks2Crypto.Xts, DevExt->Luks2Info.Key);
                DevExt->Luks2Crypto.Encrypt = Aes256XtsEncrypt;
                DevExt->Luks2Crypto.Decrypt = Aes256XtsDecrypt;
                break;
            }
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = DevExt->IsLuks2Volume;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }
    case IOCTL_DISK_GET_LENGTH_INFO:
    case IOCTL_DISK_GET_PARTITION_INFO:
    case IOCTL_DISK_GET_PARTITION_INFO_EX:
    case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: {
        PLUKS2FLT_DEVICE_CONTROL_CONTEXT Context = ExAllocateFromLookasideListEx(&gDeviceControlContextList);
        if (Context == NULL) {
            DEBUG("luks2flt!DispatchDeviceControl - ERROR: ExAllocateFromLookasideListEx returned NULL!\n");
            return FailIrp(Irp, STATUS_INSUFFICIENT_RESOURCES);
        }

        Context->Ioctl = Stack->Parameters.DeviceIoControl.IoControlCode;
        Context->Buffer = Irp->AssociatedIrp.SystemBuffer;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(
            Irp,
            Luks2FltCompleteDeviceControl,
            Context,
            TRUE,
            FALSE,
            FALSE
        );
        break;
    }
    case IOCTL_DISK_IS_WRITABLE: {
        return FailIrp(Irp, STATUS_MEDIA_WRITE_PROTECTED);
    }
    // a list of unrpoblematic (i think) ioctls i've seen in the wild before -
    // allow them and block all others because atm there are issues with the partition
    // getting corrupted
    case IOCTL_DISK_GET_DRIVE_GEOMETRY: // this returns the geometry of the disk that the volume belongs to, not the geometry of the partition
    //case IOCTL_DISK_GET_DISK_ATTRIBUTES:
    case IOCTL_STORAGE_GET_HOTPLUG_INFO:
    case IOCTL_STORAGE_GET_DEVICE_NUMBER:
    //case IOCTL_STORAGE_QUERY_PROPERTY: // this is blocked a lot...
    case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
    case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
    case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
    case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
    case IOCTL_VOLUME_IS_DYNAMIC:
        IoSkipCurrentIrpStackLocation(Irp);
        break;
    default:
        DEBUG("luks2flt!DispatchDeviceControl: DEBUG - blocking IOCTL 0x%x\n", Stack->Parameters.DeviceIoControl.IoControlCode);
        return FailIrp(Irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    return IoCallDriver(DevExt->NextLowerDevice, Irp);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchCleanup(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine for IRP_MJ_CLEANUP. Just calls DispatchPassthrough().
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    // The same reasoning as for IRP_MJ_CREATE and IRP_MJ_CLOSE applies.
    return Luks2FltDispatchPassthrough(DeviceObject, Irp);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchPower(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine for IRP_MJ_POWER. Just calls DispatchPassthrough().
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    // Decompiling the fvevol driver's FveFilterPower() routine shows that it does a lot of work in some cases,
    // but we don't care about the volume's (or rather the underlying disk's) or the system's power state,
    // so we ignore all power requests and just pass them down the stack.
    return Luks2FltDispatchPassthrough(DeviceObject, Irp);
}

_Use_decl_annotations_
NTSTATUS
Luks2FltDispatchPnp(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++
Routine Description:
    Dispatch routine for IRP_MJ_PNP. Calls DispatchPassthrough() and, if the minor function is IRP_MN_REMOVE_DEVICE,
    detaches and deletes the device.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
Return Value:
    The same as the returned value of the call to the driver of the next lower device.
--*/
{
    NTSTATUS Status;
    UCHAR MinorFunction;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    // I'm not sure what state the stack will be in and where exactly Stack will point to after IoCallDriver() returns
    // so just save the minor function for checking whether it is IRP_MN_REMOVE_DEVICE after that call
    MinorFunction = Stack->MinorFunction;

    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    // this is ok because we don't modify the IRP and don't register a completion routine. if we did
    // either of that, we'd have to use IoCopyCurrentIrpStackLocationToNext()
    IoSkipCurrentIrpStackLocation(Irp);
    Status = IoCallDriver(DevExt->NextLowerDevice, Irp);

    if (MinorFunction == IRP_MN_REMOVE_DEVICE) {
        DEBUG("luks2flt!DispatchPnp: DEBUG - received IRP_MN_REMOVE_DEVICE for device object %p\n", DeviceObject);

        // https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/removing-a-device-in-a-filter-driver says
        // "[a] filter driver follows essentially the same procedure as a function driver when removing a device", and
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/removing-a-device-in-a-function-driver
        // applied to this driver means detaching and deleting the device object.

        // a DispatchPnp() routine should always be called at IRQL = PASSIVE_LEVEL, according to
        // https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/dispatch-routines-and-irqls,
        // therefore we can detach the device and acquire the mutex
        IoDetachDevice(DevExt->NextLowerDevice);

        ExAcquireFastMutex(&gDeviceObjectCountMutex);
        for (int i = 0; i < LUKS2FLT_MAX_DEVICES; ++i) {
            if (gDeviceObjects[i] == DeviceObject) {
                IoDeleteDevice(gDeviceObjects[i]);
                gDeviceObjects[i] = NULL;
                break;
            }
        }
        ExReleaseFastMutex(&gDeviceObjectCountMutex);
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
Luks2FltCompleteRead(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
/*++
Routine Description:
    Completion routine for IRP_MJ_READ that decrypts the read data.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
    Context - a pointer that was set when registering the completion routine.
Return Value:
    Always STATUS_SUCCESS.
--*/
{
    // as a completion routine this might be called at IRQL = DISPATCH_LEVEL which is why
    // gReadContextList was initialized to allocate from non-paged memory

    // this completion routine should only be registered to be called when the lower driver
    // completed the IRP successfully
    ASSERT(Irp->IoStatus.Status == STATUS_SUCCESS);
    ASSERT(Context != NULL);

    PLUKS2FLT_READ_CONTEXT Ctx = (PLUKS2FLT_READ_CONTEXT)Context;
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    PUINT8 Buffer = MmGetSystemAddressForMdlSafe(
        Irp->MdlAddress,
        NormalPagePriority | MdlMappingNoExecute
    );

    DecryptReadBuffer(
        Buffer,
        &DevExt->Luks2Info,
        &DevExt->Luks2Crypto,
        Ctx->OrigByteOffset,
        Irp->IoStatus.Information
    );

    ExFreeToLookasideListEx(&gReadContextList, Ctx);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
Luks2FltCompleteDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
/*++
Routine Description:
    Completion routine for IRP_MJ_DEVICE_CONTROL that modifies the partition info returned
    by IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_GET_PARTITION_INFO(_EX) and IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
    and ignores all other IOCTLs.
Arguments:
    DeviceObject - the device object for the target device.
    Irp - the IRP desribing the requested IO operation.
    Context - a pointer that was set when registering the completion routine.
Return Value:
    Always STATUS_SUCCESS.
--*/
{
    UNREFERENCED_PARAMETER(Irp);

    // as a completion routine this might be called at IRQL = DISPATCH_LEVEL which is why
    // gReadContextList was initialized to allocate from non-paged memory

    // this completion routine should only be registered to be called when the lower driver
    // completed the IRP successfully
    ASSERT(Irp->IoStatus.Status == STATUS_SUCCESS);
    ASSERT(Context != NULL);

    PLUKS2FLT_DEVICE_CONTROL_CONTEXT Ctx = (PLUKS2FLT_DEVICE_CONTROL_CONTEXT)Context;
    PLUKS2FLT_DEVICE_EXTENSION DevExt = (PLUKS2FLT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    switch (Ctx->Ioctl) {
    case IOCTL_DISK_GET_PARTITION_INFO: {
        PPARTITION_INFORMATION PartInfo = (PPARTITION_INFORMATION)Ctx->Buffer;
        PartInfo->StartingOffset.QuadPart = DevExt->Luks2Info.FirstSegmentSector * DevExt->Luks2Info.SectorSize;
        PartInfo->PartitionLength.QuadPart = DevExt->Luks2Info.SegmentLength;
        break;
    }
    case IOCTL_DISK_GET_PARTITION_INFO_EX: {
        PPARTITION_INFORMATION_EX PartInfo = (PPARTITION_INFORMATION_EX)Ctx->Buffer;
        PartInfo->StartingOffset.QuadPart = DevExt->Luks2Info.FirstSegmentSector * DevExt->Luks2Info.SectorSize;
        PartInfo->PartitionLength.QuadPart = DevExt->Luks2Info.SegmentLength;
        break;
    }
    case IOCTL_DISK_GET_LENGTH_INFO: {
        PGET_LENGTH_INFORMATION LengthInfo = (PGET_LENGTH_INFORMATION)Ctx->Buffer;
        LengthInfo->Length.QuadPart = DevExt->Luks2Info.SegmentLength;
        break;
    }
    case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: {
        PVOLUME_DISK_EXTENTS Extents = (PVOLUME_DISK_EXTENTS)Ctx->Buffer;
        ASSERT(Extents->NumberOfDiskExtents == 1);
        Extents->Extents[0].StartingOffset.QuadPart = DevExt->Luks2Info.FirstSegmentSector * DevExt->Luks2Info.SectorSize;
        Extents->Extents[0].ExtentLength.QuadPart = DevExt->Luks2Info.SegmentLength;
        break;
    }
    default:
        DEBUG("luks2flt!CompleteDeviceControl: DEBUG - got unexpected IOCTL 0x%x\n", Ctx->Ioctl);
    }

    ExFreeToLookasideListEx(&gDeviceControlContextList, Ctx);

    return STATUS_SUCCESS;
}

NTSTATUS
FailIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status
)
/*++
Routine Description:
    Mark the given IRP with the given status and complete it. Irp->IoStatus.Information is set to 0.
Arguments:
    Irp - the IRP to be completed.
    Status - the Status to complete the IRP with.
Return Value:
    The same status that was given as a parameter.
--*/
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

VOID
DecryptReadBuffer(
    _Inout_ PUINT8 Buffer,
    _In_ PLUKS2_VOLUME_INFO VolInfo,
    _In_ PLUKS2_VOLUME_CRYPTO CryptoInfo,
    _In_ UINT64 OrigByteOffset,
    _In_ UINT64 Length
)
/*++
Routine Description:
    Decrypt the data in the given buffer.
Arguments:
    Buffer - the data to decrypt.
    VolInfo - information about the volume needed to decrypt the data.
    CryptoInfo - cryptographic helper structure for the volume.
    OrigByteOffset - unmodified offset in the original read request.
    Length - amount of data to decrypt.
Return Value:
    None.
--*/
{
    UINT64 Sector = OrigByteOffset / VolInfo->SectorSize;
    UINT64 Offset = 0;
    UINT8 Tweak[16];

    DEBUG("luksflt!DecryptReadBuffer: DEBUG - decrypting data: Buffer=%p Sector=%llu Length=%llu\n", Buffer, Sector, Length);

    while (Offset < Length) {
        ToLeBytes(Sector, Tweak);
        CryptoInfo->Decrypt(&CryptoInfo->Xts, Buffer + Offset, VolInfo->SectorSize, Tweak);
        Offset += VolInfo->SectorSize;
        Sector += 1;
    }
}

VOID
EncryptWriteBuffer(
    _Inout_ PUINT8 Buffer,
    _In_ PLUKS2_VOLUME_INFO VolInfo,
    _In_ PLUKS2_VOLUME_CRYPTO CryptoInfo,
    _In_ UINT64 OrigByteOffset,
    _In_ UINT64 Length
)
/*++
Routine Description:
    Encrypt the data in the given buffer.
Arguments:
    Buffer - the data to encrypt.
    VolInfo - information about the volume needed to encrypt the data.
    CryptoInfo - cryptographic helper structure for the volume.
    OrigByteOffset - unmodified offset in the original write request.
    Length - amount of data to encrypt.
Return Value:
    None.
--*/
{
    UINT64 Sector = OrigByteOffset / VolInfo->SectorSize;
    UINT64 Offset = 0;
    UINT8 Tweak[16];

    DEBUG("luksflt!EncryptWriteBuffer: DEBUG - encrypting data: Buffer=%p Sector=%llu Length=%llu\n", Buffer, Sector, Length);

    while (Offset < Length) {
        ToLeBytes(Sector, Tweak);
        CryptoInfo->Encrypt(&CryptoInfo->Xts, Buffer + Offset, VolInfo->SectorSize, Tweak);
        Offset += VolInfo->SectorSize;
        Sector += 1;
    }
}

VOID
DumpBuffer(
    _In_ PUINT8 Buffer,
    _In_ UINT64 Length
)
/*++
Routine Description:
    Dumps up to 4096 bytes from Buffer to the debug output.
Arguments:
    Buffer - the buffer to dump.
    Length - bow many bytes to dump (values greater than 1024 are capped to 1024).
Return Value:
    None.
--*/
{
    // So that this also compiles without debugging enabled
    UNREFERENCED_PARAMETER(Buffer);

    Length = min(Length, 4096);
    DEBUG("luksflt!DumpBuffer: DEBUG - dumping buffer (%llu bytes):", Length);
    for (UINT64 i = 0; i < Length; ++i) {
        if ((i != 0) && (i % 512) == 0)
            DEBUG("\n");
        if ((i % 32) == 0)
            DEBUG("\n\t");
        DEBUG("0x%02x, ", Buffer[i]);
    }
    DEBUG("\n");
}