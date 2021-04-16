/*
* The following code is a translation of relevant parts of the Rust aes crate, found at
* https://github.com/RustCrypto/Block-ciphers/tree/7236bce0b75b7bcf719add5e88890bd667ebb95f/aes/src/ni. The originial code is copyright protected and
* licensed as follows.
* 
* Copyright 2020 RustCrypto Developers
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

#define _Aes128InitExpand() \
    __m128i t1; \
    __m128i t2; \
    __m128i t3;

#define _Aes128ExpandRound(EncKeys, DecKeys, Pos, Round) \
    t1 = _mm_load_si128(EncKeys + Pos - 1);    \
    t2 = _mm_aeskeygenassist_si128(t1, Round);  \
    t2 = _mm_shuffle_epi32(t2, 0xff);           \
    t3 = _mm_slli_si128(t1, 0x4);               \
    t1 = _mm_xor_si128(t1, t3);                 \
    t3 = _mm_slli_si128(t3, 0x4);               \
    t1 = _mm_xor_si128(t1, t3);                 \
    t3 = _mm_slli_si128(t3, 0x4);               \
    t1 = _mm_xor_si128(t1, t3);                 \
    t1 = _mm_xor_si128(t1, t2);                 \
    _mm_store_si128(EncKeys + Pos, t1);        \
    t1 = _mm_aesimc_si128(t1);              \
    _mm_store_si128(DecKeys + Pos, t1);

#define _Aes128ExpandRound_last(EncKeys, DecKeys, Pos, Round) \
    t1 = _mm_load_si128(EncKeys + Pos - 1);    \
    t2 = _mm_aeskeygenassist_si128(t1, Round);  \
    t2 = _mm_shuffle_epi32(t2, 0xff);           \
    t3 = _mm_slli_si128(t1, 0x4);               \
    t1 = _mm_xor_si128(t1, t3);                 \
    t3 = _mm_slli_si128(t3, 0x4);               \
    t1 = _mm_xor_si128(t1, t3);                 \
    t3 = _mm_slli_si128(t3, 0x4);               \
    t1 = _mm_xor_si128(t1, t3);                 \
    t1 = _mm_xor_si128(t1, t2);                 \
    _mm_store_si128(EncKeys + Pos, t1);        \
    _mm_store_si128(DecKeys + Pos, t1);

VOID _Aes128ExpandKeys(PUINT8 Key, __m128i *EncKeys, __m128i *DecKeys) {
    __m128i k = _mm_loadu_si128((__m128i *) Key);
    _mm_store_si128(EncKeys, k);
    _mm_store_si128(DecKeys, k);
    _Aes128InitExpand();
    _Aes128ExpandRound(EncKeys, DecKeys, 1, 0x01);
    _Aes128ExpandRound(EncKeys, DecKeys, 2, 0x02);
    _Aes128ExpandRound(EncKeys, DecKeys, 3, 0x04);
    _Aes128ExpandRound(EncKeys, DecKeys, 4, 0x08);
    _Aes128ExpandRound(EncKeys, DecKeys, 5, 0x10);
    _Aes128ExpandRound(EncKeys, DecKeys, 6, 0x20);
    _Aes128ExpandRound(EncKeys, DecKeys, 7, 0x40);
    _Aes128ExpandRound(EncKeys, DecKeys, 8, 0x80);
    _Aes128ExpandRound(EncKeys, DecKeys, 9, 0x1B);
    _Aes128ExpandRound_last(EncKeys, DecKeys, 10, 0x36);
}

VOID Aes128Init(PAES128 Aes, PUINT8 Key) {
    _Aes128ExpandKeys(Key, Aes->EncryptKeys, Aes->DecryptKeys);
}

__m128i Aes128Encrypt(PAES128 Aes, __m128i Block) {
    Block = _mm_xor_si128(Block, Aes->EncryptKeys[0]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[1]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[2]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[3]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[4]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[5]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[6]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[7]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[8]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[9]);
    return _mm_aesenclast_si128(Block, Aes->EncryptKeys[10]);
}

__m128i Aes128Decrypt(PAES128 Aes, __m128i Block) {
    Block = _mm_xor_si128(Block, Aes->DecryptKeys[10]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[9]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[8]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[7]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[6]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[5]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[4]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[3]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[2]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[1]);
    return _mm_aesdeclast_si128(Block, Aes->DecryptKeys[0]);
}

#define _Aes256InitExpand() \
    __m128i t;  \
    __m128i t1; \
    __m128i t2; \
    __m128i t3; \
    __m128i t4;

#define _Aes256ExpandRound(EncKeys, DecKeys, Pos, Round) \
	t1 = _mm_load_si128(EncKeys + Pos - 2);    \
	t3 = _mm_load_si128(EncKeys + Pos - 1);    \
	t2 = _mm_aeskeygenassist_si128(t3, Round);  \
    t2 = _mm_shuffle_epi32(t2, 0xff);           \
    t4 = _mm_slli_si128(t1, 0x4);               \
    t1 = _mm_xor_si128(t1, t4);                 \
    t4 = _mm_slli_si128(t4, 0x4);               \
    t1 = _mm_xor_si128(t1, t4);                 \
    t4 = _mm_slli_si128(t4, 0x4);               \
    t1 = _mm_xor_si128(t1, t4);                 \
    t1 = _mm_xor_si128(t1, t2);                 \
    _mm_store_si128(EncKeys + Pos, t1);        \
    t = _mm_aesimc_si128(t1);           \
    _mm_store_si128(DecKeys + Pos, t);         \
    t4 = _mm_aeskeygenassist_si128(t1, 0x00);   \
    t2 = _mm_shuffle_epi32(t4, 0xaa);           \
    t4 = _mm_slli_si128(t3, 0x4);               \
    t3 = _mm_xor_si128(t3, t4);                 \
    t4 = _mm_slli_si128(t4, 0x4);               \
    t3 = _mm_xor_si128(t3, t4);                 \
    t4 = _mm_slli_si128(t4, 0x4);               \
    t3 = _mm_xor_si128(t3, t4);                 \
    t3 = _mm_xor_si128(t3, t2);                 \
    _mm_store_si128(EncKeys + Pos + 1, t3);    \
    t = _mm_aesimc_si128(t3);                   \
    _mm_store_si128(DecKeys + Pos + 1, t);

#define _Aes256ExpandRoundLast(EncKeys, DecKeys, Pos, Round) \
    t1 = _mm_load_si128(EncKeys + Pos - 2);    \
	t3 = _mm_load_si128(EncKeys + Pos - 1);    \
    t2 = _mm_aeskeygenassist_si128(t3, Round);  \
    t2 = _mm_shuffle_epi32(t2, 0xff);           \
    t4 = _mm_slli_si128(t1, 0x4);               \
    t1 = _mm_xor_si128(t1, t4);                 \
    t4 = _mm_slli_si128(t4, 0x4);               \
    t1 = _mm_xor_si128(t1, t4);                 \
    t4 = _mm_slli_si128(t4, 0x4);               \
    t1 = _mm_xor_si128(t1, t4);                 \
    t1 = _mm_xor_si128(t1, t2);                 \
    _mm_store_si128(EncKeys + Pos, t1);        \
    _mm_store_si128(DecKeys + Pos, t1);

VOID _Aes256ExpandKeys(PUINT8 Key, __m128i *EncKeys, __m128i *DecKeys) {
    __m128i *kp = (__m128i *) Key;
    __m128i k1 = _mm_loadu_si128(kp);
    __m128i k2 = _mm_loadu_si128(kp + 1);
    _mm_store_si128(EncKeys, k1);
    _mm_store_si128(DecKeys, k1);
    _mm_store_si128(EncKeys + 1, k2);
    _mm_store_si128(DecKeys + 1, _mm_aesimc_si128(k2));
    _Aes256InitExpand();
    _Aes256ExpandRound(EncKeys, DecKeys, 2, 0x01);
    _Aes256ExpandRound(EncKeys, DecKeys, 4, 0x02);
    _Aes256ExpandRound(EncKeys, DecKeys, 6, 0x04);
    _Aes256ExpandRound(EncKeys, DecKeys, 8, 0x08);
    _Aes256ExpandRound(EncKeys, DecKeys, 10, 0x10);
    _Aes256ExpandRound(EncKeys, DecKeys, 12, 0x20);
    _Aes256ExpandRoundLast(EncKeys, DecKeys, 14, 0x40);
}

VOID Aes256Init(PAES256 Aes, PUINT8 Key) {
    _Aes256ExpandKeys(Key, Aes->EncryptKeys, Aes->DecryptKeys);
}

__m128i Aes256Encrypt(PAES256 Aes, __m128i Block) {
    Block = _mm_xor_si128(Block, Aes->EncryptKeys[0]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[1]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[2]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[3]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[4]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[5]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[6]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[7]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[8]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[9]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[10]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[11]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[12]);
    Block = _mm_aesenc_si128(Block, Aes->EncryptKeys[13]);
    return _mm_aesenclast_si128(Block, Aes->EncryptKeys[14]);
}

__m128i Aes256Decrypt(PAES256 Aes, __m128i Block) {
    Block = _mm_xor_si128(Block, Aes->DecryptKeys[14]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[13]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[12]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[11]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[10]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[9]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[8]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[7]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[6]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[5]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[4]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[3]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[2]);
    Block = _mm_aesdec_si128(Block, Aes->DecryptKeys[1]);
    return _mm_aesdeclast_si128(Block, Aes->DecryptKeys[0]);
}

__m128i BytesToBlock(PUINT8 Bytes) {
    return _mm_loadu_si128((__m128i *) Bytes);
}

VOID BlockToBytes(__m128i Block, PUINT8 Bytes) {
    INT64 Lower = _mm_cvtsi128_si64(Block);
    Block = _mm_srli_si128(Block, 8);
    INT64 Upper = _mm_cvtsi128_si64(Block);
    for (int i = 0; i < 8; ++i)
        Bytes[i] = (Lower & (0xFFULL << (i * 8))) >> (i * 8);
    for (int i = 0; i < 8; ++i)
        Bytes[i + 8] = (Upper & (0xFFULL << (i * 8))) >> (i * 8);
}
