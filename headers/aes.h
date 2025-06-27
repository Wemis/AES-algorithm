#ifndef AES_H
#define AES_H
#include <stdint.h>
#include <stddef.h>

void AES_128_block_encrypt(uint8_t** block, uint8_t expandedKey[11][4][4]);
void AES_128_block_decrypt(uint8_t** block, uint8_t expandedKey[11][4][4]);
int AES_128_CBC_encrypt(const uint8_t key[16], const uint8_t iv[16], const unsigned char* buffer, size_t buffer_size, uint8_t* buffer_encrypted, int* size);
int AES_128_CBC_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t* buffer, size_t buffer_size, uint8_t* buffer_decrypted, int* size);

#endif