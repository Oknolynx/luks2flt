/*
* The following code is a translation of relevant parts of the Rust Xts-mode crate, found at
* https://github.com/pheki/Xts-mode/blob/3188ca0fd434d060dc9a3dde57597797699110e6/src/lib.rs. The originial code is copyright protected and
* licensed as follows.
* 
* Copyright 2020 Aphek Brito
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE.
*/

#include "luks2flt.h"

enum _AesVariant {
	_AES128,
	_AES256
};

enum _CipherVariant {
	Cipher1,
	Cipher2
};

VOID XtsEncrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak, enum _AesVariant AesVariant);
VOID XtsDecrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak, enum _AesVariant AesVariant);
VOID EncryptBlock(PXTS Xts, PUINT8 Data, enum _AesVariant AesVariant, enum _CipherVariant CipherVariant);
VOID DecryptBlock(PXTS Xts, PUINT8 Data, enum _AesVariant AesVariant, enum _CipherVariant CipherVariant);
VOID Xor(PUINT8 Buf, PUINT8 Key);
VOID GaloisField128MulLe(PUINT8 Tweak);

VOID Aes128XtsInit(PXTS Xts, PUINT8 Key) {
	Aes128Init(&Xts->Aes128.Cipher1, Key);
	Aes128Init(&Xts->Aes128.Cipher2, Key + 16);
}

VOID Aes128XtsEncrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak) {
	XtsEncrypt(Xts, Sector, SectorSize, Tweak, _AES128);
}

VOID Aes128XtsDecrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak) {
	XtsDecrypt(Xts, Sector, SectorSize, Tweak, _AES128);
}

VOID Aes256XtsInit(PXTS Xts, PUINT8 key) {
	Aes256Init(&Xts->Aes256.Cipher1, key);
	Aes256Init(&Xts->Aes256.Cipher2, key + 32);
}

VOID Aes256XtsEncrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak) {
	XtsEncrypt(Xts, Sector, SectorSize, Tweak, _AES256);
}

VOID Aes256XtsDecrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak) {
	XtsDecrypt(Xts, Sector, SectorSize, Tweak, _AES256);
}

VOID ToLeBytes(UINT64 N, PUINT8 Bytes) {
	for (int i = 0; i < 8; ++i)
        Bytes[i] = (N & (0xFFULL << (i * 8))) >> (i * 8);
	memset(Bytes + 8, 0, 8);
}

VOID XtsEncrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak, enum _AesVariant AesVariant) {
	UINT64 BlockCount = SectorSize / 16;
	BOOLEAN NeedStealing = (SectorSize % 16) != 0;

	EncryptBlock(Xts, Tweak, AesVariant, Cipher2);

	UINT64 NostealBlockCount = NeedStealing ? BlockCount - 1 : BlockCount;
	for (UINT64 i = 0, c = 0; c < NostealBlockCount; i += 16, c += 1) {
		Xor(Sector + i, Tweak);
		DecryptBlock(Xts, Sector + i, AesVariant, Cipher1);
		Xor(Sector + i, Tweak);
		GaloisField128MulLe(Tweak);
	}

	if (NeedStealing) {
		UINT8 NextToLastTweak[16];
		PUINT8 LastTweak = Tweak;
		UINT64 remaining = SectorSize % 16;
		PUINT8 Block = Sector + 16*(BlockCount - 1);

		memcpy(NextToLastTweak, Tweak, 16);
		GaloisField128MulLe(LastTweak);
		Xor(Block, NextToLastTweak);

		UINT8 LastBlock[16];
		memcpy(LastBlock, Sector + 16*BlockCount, remaining);
		memcpy(LastBlock + remaining, Block + remaining, 16 - remaining);
		Xor(LastBlock, LastTweak);
		EncryptBlock(Xts, LastBlock, AesVariant, Cipher1);
		Xor(LastBlock, LastTweak);

		memcpy(Sector + 16*(BlockCount - 1), LastBlock, 16);
		memcpy(Sector + 16*BlockCount, Block, remaining);
	}
}

VOID XtsDecrypt(PXTS Xts, PUINT8 Sector, UINT64 SectorSize, PUINT8 Tweak, enum _AesVariant AesVariant) {
	UINT64 BlockCount = SectorSize / 16;
	BOOLEAN NeedStealing = (SectorSize % 16) != 0;

	EncryptBlock(Xts, Tweak, AesVariant, Cipher2);

	UINT64 NostealBlockCount = NeedStealing ? BlockCount - 1 : BlockCount;
	for (UINT64 i = 0, c = 0; c < NostealBlockCount; i += 16, c += 1) {
		Xor(Sector + i, Tweak);
		DecryptBlock(Xts, Sector + i, AesVariant, Cipher1);
		Xor(Sector + i, Tweak);
		GaloisField128MulLe(Tweak);
	}

	if (NeedStealing) {
		UINT8 NextToLastTweak[16];
		PUINT8 LastTweak = Tweak;
		UINT64 remaining = SectorSize % 16;
		PUINT8 Block = Sector + 16*(BlockCount - 1);

		memcpy(NextToLastTweak, Tweak, 16);
		GaloisField128MulLe(LastTweak);
		Xor(Block, LastTweak);
		DecryptBlock(Xts, Block, AesVariant, Cipher1);
		Xor(Block, LastTweak);

		UINT8 LastBlock[16];
		memcpy(LastBlock, Sector + 16*BlockCount, remaining);
		memcpy(LastBlock + remaining, Block + remaining, 16 - remaining);
		Xor(LastBlock, NextToLastTweak);
		DecryptBlock(Xts, LastBlock, AesVariant, Cipher1);
		Xor(LastBlock, NextToLastTweak);

		memcpy(Sector + 16*(BlockCount - 1), LastBlock, 16);
		memcpy(Sector + 16*BlockCount, Block, remaining);
	}
}

VOID EncryptBlock(PXTS Xts, PUINT8 data, enum _AesVariant AesVariant, enum _CipherVariant CipherVariant) {
	__m128i Block = BytesToBlock(data);
	switch (AesVariant) {
	case _AES128:
		switch (CipherVariant) {
		case Cipher1:
			Block = Aes128Encrypt(&Xts->Aes128.Cipher1, Block);
			break;
		case Cipher2:
			Block = Aes128Encrypt(&Xts->Aes128.Cipher2, Block);
			break;
		}
		break;
	case _AES256:
		switch (CipherVariant) {
		case Cipher1:
			Block = Aes256Encrypt(&Xts->Aes256.Cipher1, Block);
			break;
		case Cipher2:
			Block = Aes256Encrypt(&Xts->Aes256.Cipher2, Block);
			break;
		}
		break;
	}
	BlockToBytes(Block, data);
}

VOID DecryptBlock(PXTS Xts, PUINT8 data, enum _AesVariant AesVariant, enum _CipherVariant CipherVariant) {
	__m128i Block = BytesToBlock(data);
	switch (AesVariant) {
	case _AES128:
		switch (CipherVariant) {
		case Cipher1:
			Block = Aes128Decrypt(&Xts->Aes128.Cipher1, Block);
			break;
		case Cipher2:
			Block = Aes128Decrypt(&Xts->Aes128.Cipher2, Block);
			break;
		}
		break;
	case _AES256:
		switch (CipherVariant) {
		case Cipher1:
			Block = Aes256Decrypt(&Xts->Aes256.Cipher1, Block);
			break;
		case Cipher2:
			Block = Aes256Decrypt(&Xts->Aes256.Cipher2, Block);
			break;
		}
		break;
	}
	BlockToBytes(Block, data);
}

VOID Xor(PUINT8 Buf, PUINT8 Key) {
	for (int i = 0; i < 16; ++i)
		Buf[i] ^= Key[i];
}

VOID GaloisField128MulLe(PUINT8 Tweak) {
	UINT64 lower = Tweak[0] | (UINT64) Tweak[1] << 8 | (UINT64) Tweak[2] << 16 | (UINT64) Tweak[3] << 24
		| (UINT64) Tweak[4] << 32 | (UINT64) Tweak[5] << 40 | (UINT64) Tweak[6] << 48 | (UINT64) Tweak[7] << 56;
	UINT64 upper = Tweak[8] | (UINT64) Tweak[9] << 8 | (UINT64) Tweak[10] << 16 | (UINT64) Tweak[11] << 24
		| (UINT64) Tweak[12] << 32 | (UINT64) Tweak[13] << 40 | (UINT64) Tweak[14] << 48 | (UINT64) Tweak[15] << 56;

	UINT64 new_lower = (lower << 1) ^ ((upper >> 63) != 0 ? 0x87 : 0x00);
	UINT64 new_upper = (lower >> 63) | (upper << 1);

	for (int i = 0; i < 8; ++i)
        Tweak[i] = (new_lower & (0xFFULL << (i * 8))) >> (i * 8);
    for (int i = 0; i < 8; ++i)
        Tweak[i + 8] = (new_upper & (0xFFULL << (i * 8))) >> (i * 8);
}