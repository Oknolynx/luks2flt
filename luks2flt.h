#pragma once

#include <immintrin.h> // for AES intrinsics
#include <intrin.h> // for AES intrinsics
#include <ntddk.h>
#include <ntdddisk.h> // for various IOCTLs and PARTITION_INFORMATION(_EX)
#include <ntddvol.h> // for IOCTL_VOLUME_* IOCTLs
#include <mountdev.h> // for IOCTL_MOUNTDEV_* IOCTLs
#include <mountmgr.h> // for IOCTL_MOUNTDEV_* IOCTLs
#include <wdm.h>

/* === Constants and macros === */
// the maximum number of device objects this driver may create
#define LUKS2FLT_MAX_DEVICES 32
//#define DO_DEBUG
#ifdef DO_DEBUG
// log everything as errors (for now) so that WinDbg must not be configured to show our messages
#define DEBUG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#else
#define DEBUG(...)
#endif
#define IRQL_ASSERT(Irql) ASSERT(KeGetCurrentIrql() == Irql)
// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes says the first value supplied
// to CTL_CODE "must match the value that is set in the DeviceType member of the driver's DEVICE_OBJECT". the function code
// is a random number between 0x800 and 0xFFF (as values below 0x800 are reserved for Microsoft).
#define IOCTL_DISK_SET_LUKS2_INFO CTL_CODE(FILE_DEVICE_DISK, 0x0c38, METHOD_BUFFERED, FILE_WRITE_ACCESS)


// memory allocation tags
#define READCTX_TAG 'R2SL' // 'LS2R' backwards
#define DEVCTLCTX_TAG 'D2SL' // 'LS2D' backwards

/* === Type definitions === */
// AES(-XTS) types
typedef struct _AES128 {
    __m128i EncryptKeys[11];
    __m128i DecryptKeys[11];
} AES128, * PAES128;

typedef struct _AES256 {
    __m128i EncryptKeys[15];
    __m128i DecryptKeys[15];
} AES256, * PAES256;

struct _AES128_XTS {
    AES128 Cipher1;
    AES128 Cipher2;
};

struct _AES256_XTS {
    AES256 Cipher1;
    AES256 Cipher2;
};

typedef union _XTS {
    struct _AES128_XTS Aes128;
    struct _AES256_XTS Aes256;
} XTS, * PXTS;

// The two supported encryption algorithms for LUKS2 volumes.
typedef enum _LUKS2_ENCRYPTION_VARIANT {
    AES_128_XTS = 0,
    AES_256_XTS = 1
} LUKS2_ENCRYPTION_VARIANT, * PLUKS2_ENCRYPTION_VARIANT;

// Information about a LUKS2 volume as provided with an IOCTL_LUKS2FLT_SET_LUKS2_INFO.
typedef struct LUKS2_VOLUME_INFO {
    // Sector size of the volume.
    UINT16 SectorSize;

    // First sector of the LUKS2 segment (where the encrypted data is stored).
    UINT64 FirstSegmentSector;

    // Length of the LUKS2 segment in bytes.
    UINT64 SegmentLength;

    // Encryption algorithm used for the volume.
    LUKS2_ENCRYPTION_VARIANT EncVariant;

    // Master key of this volume. In case AES-128-XTS is used, only the first 32 bytes are used;
    // AES-256-XTS uses all 64 bytes.
    UINT8 Key[64];
} LUKS2_VOLUME_INFO, * PLUKS2_VOLUME_INFO;

// Cryptographic helper structure for a LUKS2 volumes.
typedef struct _LUKS2_VOLUME_CRYPTO {
    // XTS structure used for en-/decryption.
    XTS Xts;

    // Function to encrypt one sector using this struct's Xts member.
    VOID(*Encrypt)(PXTS, PUINT8, UINT64, PUINT8);

    // Function to decrypt one sector using this struct's Xts member.
    VOID(*Decrypt)(PXTS, PUINT8, UINT64, PUINT8);
} LUKS2_VOLUME_CRYPTO, * PLUKS2_VOLUME_CRYPTO;

// Device extension for device objects created by this driver.
typedef struct _LUKS2FLT_DEVICE_EXTENSION {
    // Pointer to the next lower device in the device stack the device is attached to.
    PDEVICE_OBJECT NextLowerDevice;

    // Flag for whether this is a LUKS2 volume. Set via IOCTL_DISK_SET_LUKS2_INFO.
    BOOLEAN IsLuks2Volume;

    // More information about the LUKS2 volume. Set via IOCTL_DISK_SET_LUKS2_INFO.
    LUKS2_VOLUME_INFO Luks2Info;

    // Cryptographic helper structure for the LUKS2 volume.
    LUKS2_VOLUME_CRYPTO Luks2Crypto;
} LUKS2FLT_DEVICE_EXTENSION, * PLUKS2FLT_DEVICE_EXTENSION;

// Context that is passed to the IRP_MJ_READ completion routine.
typedef struct _LUKS2FLT_READ_CONTEXT {
    // Read offset of the original request so that the sector can be calculated
    // (needed for decryption);
    UINT64 OrigByteOffset;
} LUKS2FLT_READ_CONTEXT, * PLUKS2FLT_READ_CONTEXT;

// Context that is passed to the IRP_MJ_DEVICE_CONTROL completion routine.
typedef struct _LUKS2FLT_DEVICE_CONTROL_CONTEXT {
    // IOCTL of the request.
    ULONG Ioctl;

    // Set to thw value of Irp->AssociatedIrp.SystemBuffer.
    PVOID Buffer;
} LUKS2FLT_DEVICE_CONTROL_CONTEXT, * PLUKS2FLT_DEVICE_CONTROL_CONTEXT;

/* === Driver routine declarations === */
DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE Luks2FltAddDevice;
DRIVER_UNLOAD     Luks2FltUnload;
// actually this is the dispatch routine for all types, but this annotation makes the code analysis happy
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH   Luks2FltDispatchGeneric;
DRIVER_DISPATCH   Luks2FltDispatchPassthrough;
DRIVER_DISPATCH   Luks2FltDispatchCreateClose;
DRIVER_DISPATCH   Luks2FltDispatchRead;
DRIVER_DISPATCH   Luks2FltDispatchWrite;
DRIVER_DISPATCH   Luks2FltDispatchDeviceControl;
DRIVER_DISPATCH   Luks2FltDispatchCleanup;
DRIVER_DISPATCH   Luks2FltDispatchPower;
DRIVER_DISPATCH   Luks2FltDispatchPnp;

IO_COMPLETION_ROUTINE Luks2FltCompleteRead;
IO_COMPLETION_ROUTINE Luks2FltCompleteDeviceControl;

NTSTATUS
FailIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status
);

VOID
DecryptReadBuffer(
    _Inout_ PUINT8 Buffer,
    _In_ PLUKS2_VOLUME_INFO VolInfo,
    _In_ PLUKS2_VOLUME_CRYPTO CryptoInfo,
    _In_ UINT64 ByteOffset,
    _In_ UINT64 Length
);

VOID
EncryptWriteBuffer(
    _Inout_ PUINT8 Buffer,
    _In_ PLUKS2_VOLUME_INFO VolInfo,
    _In_ PLUKS2_VOLUME_CRYPTO CryptoInfo,
    _In_ UINT64 ByteOffset,
    _In_ UINT64 Length
);

VOID
DumpBuffer(
    _In_ PUINT8 Buffer,
    _In_ UINT64 Length
);

// AES functions

// Initialize the caller-allocated aes128 struct with the given key.
// The buffer that key points to must be at least 128 bits (16 bytes) long
// and the first 16 bytes will be used as the key.
VOID Aes128Init(PAES128 Aes, PUINT8 Key);

// Encrypt one block of data using the initialized aes128 struct.
__m128i Aes128Encrypt(PAES128 Aes, __m128i Block);

// Decrypt one block of data using the initialized aes128 struct.
__m128i Aes128Decrypt(PAES128 Aes, __m128i Block);

// Initialize the caller-allocated aes128 struct with the given key.
// The buffer that key points to must be at least 256 bits (32 bytes) long
// and the first 32 bytes will be used as the key.
VOID Aes256Init(PAES256 Aes, PUINT8 Key);

// Encrypt one block of data using the initialized aes256 struct.
__m128i Aes256Encrypt(PAES256 Aes, __m128i Block);

// Decrypt one block of data using the initialized aes256 struct.
__m128i Aes256Decrypt(PAES256 Aes, __m128i Block);

// Convenience function to extract the first 128 bits that bytes points to
// into a __m128i.
__m128i BytesToBlock(PUINT8 Bytes);

// Convenience function to store the value in block into the first 16 bytes
// of bytes.
VOID BlockToBytes(__m128i Block, PUINT8 Bytes);

// AES-XTS functions

// Initialize the caller-allocated aes128_xts struct with the given key.
// The buffer that key points to must be at least 2*128 bits (32 bytes) long;
// the first 16 bytes will be used as the key for the blocks and the second
// 16 bytes will be used for computing the tweak at each sector start.
VOID Aes128XtsInit(PXTS Xts, PUINT8 Key);

// Encrypt one sector in place using the AES128-initialized xts struct and the
// given tweak.
// The sector must contain at least a single block, i. e. at least 16 bytes.
// The sector size is specified in bytes. The tweak must be (at least) 16 bytes long.
VOID Aes128XtsEncrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak);

// Decrypt one sector in place using the AES128-initialized xts struct and the
// given tweak.
// The sector must contain at least a single block, i. e. at least 16 bytes.
// The sector size is specified in bytes. The tweak must be (at least) 16 bytes long.
VOID Aes128XtsDecrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak);

// Initialize the caller-allocated aes256_xts struct with the given key.
// The buffer that key points to must be at least 2*256 bits (64 bytes) long;
// the first 32 bytes will be used as the key for the blocks and the second
// 32 bytes will be used for computing the tweak at each sector start.
VOID Aes256XtsInit(PXTS Xts, PUINT8 Key);

// Encrypt one sector in place using the AES256-initialized xts struct and the
// given tweak.
// The sector must contain at least a single block, i. e. at least 16 bytes.
// The sector size is specified in bytes. The tweak must be (at least) 16 bytes long.
VOID Aes256XtsEncrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak);

// Decrypt one sector in place using the AES256-initialized xts struct and the
// given tweak.
// The sector must contain at least a single block, i. e. at least 16 bytes.
// The sector size is specified in bytes. The tweak must be (at least) 16 bytes long.
VOID Aes256XtsDecrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak);

// Convenience function to convert the given number to 16 little-endian bytes.
VOID ToLeBytes(UINT64 N, PUINT8 Bytes);