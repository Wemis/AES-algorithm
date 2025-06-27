#ifndef AES_CORE_H
#define AES_CORE_H
#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

void SubWord(uint8_t word[4]);
void RotWord(uint8_t word[4]);
void SubBytes(uint8_t** state);
void InvSubBytes(uint8_t** state);
void ShiftRows(uint8_t** state);
void InvShiftRows(uint8_t** state);
void KeyExpansion(const uint8_t key[4][4], uint8_t expandedKey[11][4][4]);
void MixColumns(uint8_t** state);
void InvMixColumns(uint8_t** state);
void AddRoundKey(uint8_t** state, uint8_t key[4][4]);

#endif