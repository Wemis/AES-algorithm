#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include "headers/aes_core.h"

#define AES_SUCCESS 1
#define BUFFER_TOO_SMALL 2
#define BUFFER_DAMAGED 3
#define PADDING_ERROR 4

void AES_128_block_encrypt(uint8_t** block, uint8_t expandedKey[11][4][4]) {
    AddRoundKey(block, expandedKey[0]);

    for (int round = 1; round < 10; round++) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, expandedKey[round]);
    }

    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, expandedKey[10]);
}

void AES_128_block_decrypt(uint8_t** block, uint8_t expandedKey[11][4][4]) {
    AddRoundKey(block, expandedKey[10]);

    for (int round = 9; round >= 1; round--) {
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, expandedKey[round]);
        InvMixColumns(block);
    }

    InvShiftRows(block);
    InvSubBytes(block);
    AddRoundKey(block, expandedKey[0]);
}

int AES_128_CBC_encrypt(const uint8_t key[16], const uint8_t iv[16], const unsigned char* buffer, size_t buffer_size, uint8_t* buffer_encrypted, int* size) {
    size_t n_full_blocks = (buffer_size - (buffer_size % AES_BLOCK_SIZE)) / AES_BLOCK_SIZE;
    size_t n_extra_bytes = buffer_size % AES_BLOCK_SIZE;
    
    size_t n_blocks = n_full_blocks + 1;

    // Allocating memory for data blocks
    uint8_t*** blocks = malloc(n_blocks * sizeof(uint8_t**));
    for (size_t block = 0; block < n_blocks; block++) {
        blocks[block] = malloc(4 * sizeof(uint8_t*));
        for (size_t col = 0; col < 4; col++) {
            blocks[block][col] = malloc(4 * sizeof(uint8_t));
        }
    }

    // Copying data to structured data blocks
    size_t buffer_index = 0;
    for (size_t block = 0; block < n_full_blocks; block++) {
        for (size_t col = 0; col < 4; col++) {
            for (size_t row = 0; row < 4; row++) {
                blocks[block][col][row] = buffer[buffer_index];
                buffer_index++;
            }
        }
    }

    // Padding PKCS#7
    if (n_extra_bytes != 0) {
        uint8_t padding_byte = (uint8_t)(AES_BLOCK_SIZE - n_extra_bytes);

        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                blocks[n_blocks - 1][col][row] = padding_byte;
            }
        }

        if (n_extra_bytes >= 4) {
            for (uint8_t col = 0; col < (n_extra_bytes - (n_extra_bytes % 4)) / 4; col++) {
                for (uint8_t row = 0; row < 4; row++) {
                    blocks[n_blocks - 1][col][row] = buffer[buffer_index];
                    buffer_index++;
                }
            }
            if ((n_extra_bytes % 4) != 0) {
                for (uint8_t i = 0; i < (n_extra_bytes % 4); i++) {
                    blocks[n_blocks - 1][(n_extra_bytes - (n_extra_bytes % 4)) / 4][i] = buffer[buffer_index];
                    buffer_index++;
                }
            }
        } else {
            for (uint8_t i = 0; i < n_extra_bytes; i++) {
                blocks[n_blocks - 1][0][i] = buffer[buffer_index];
                buffer_index++;
            }
        }
    
    } else {
        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                blocks[n_blocks - 1][col][row] = 0x10;
            }
        }
    }

    uint8_t expandedKey[11][4][4];
    uint8_t key_matrix[4][4];

    uint8_t key_i = 0;
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            key_matrix[col][row] = key[key_i];
            key_i++;
        }
    }

    KeyExpansion(key_matrix, expandedKey);

    // Encryption block-by-block and Cipher Block Chaining
    uint8_t previous_block[4][4];
    uint8_t iv_i = 0;
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            previous_block[col][row] = iv[iv_i];
            iv_i++;
        }
    }
    for (size_t block = 0; block < n_blocks; block++) {
        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                blocks[block][col][row] ^= previous_block[col][row];
            }
        }

        AES_128_block_encrypt(blocks[block], expandedKey);

        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                previous_block[col][row] = blocks[block][col][row];
            }
        }
    }

    buffer_index = 0;
    for (size_t block = 0; block < n_blocks; block++) {
        for (size_t col = 0; col < 4; col++) {
            for (size_t row = 0; row < 4; row++) {
                buffer_encrypted[buffer_index] = blocks[block][col][row];
                buffer_index++;
            }
        }
    }

    for (size_t block = 0; block < n_blocks; block++) {
        for (size_t col = 0; col < 4; col++) {
            free(blocks[block][col]);
        }
        free(blocks[block]);
    }
    free(blocks);

    *size = n_blocks * AES_BLOCK_SIZE;
    return AES_SUCCESS;
}


int AES_128_CBC_decrypt(const uint8_t key[16], uint8_t iv[16], const uint8_t* buffer, size_t buffer_size, uint8_t* buffer_decrypted, int* size) {
    if ((buffer_size % AES_BLOCK_SIZE) != 0 || buffer_size == 0) {
        return 0;
    }

    size_t n_blocks = buffer_size / AES_BLOCK_SIZE;

    // Allocating memory for data blocks
    uint8_t*** blocks = malloc(n_blocks * sizeof(uint8_t**));
    for (size_t block = 0; block < n_blocks; block++) {
        blocks[block] = malloc(4 * sizeof(uint8_t*));
        for (size_t col = 0; col < 4; col++) {
            blocks[block][col] = malloc(4 * sizeof(uint8_t));
        }
    }

    // Copying data to structured data blocks
    size_t buffer_index = 0;
    for (size_t block = 0; block < n_blocks; block++) {
        for (size_t col = 0; col < 4; col++) {
            for (size_t row = 0; row < 4; row++) {
                blocks[block][col][row] = buffer[buffer_index];
                buffer_index++;
            }
        }
    }

    uint8_t expandedKey[11][4][4];
    uint8_t key_matrix[4][4];

    uint8_t key_i = 0;
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            key_matrix[col][row] = key[key_i];
            key_i++;
        }
    }

    KeyExpansion(key_matrix, expandedKey);

    // Decryption block-by-block and Cipher Block Chaining
    uint8_t previous_block[4][4];
    uint8_t temp[4][4];
    uint8_t iv_i = 0;
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            previous_block[col][row] = iv[iv_i];
            iv_i++;
        }
    }
    for (size_t block = 0; block < n_blocks; block++) {
        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                temp[col][row] = blocks[block][col][row];
            }
        }

        AES_128_block_decrypt(blocks[block], expandedKey);

        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                blocks[block][col][row] ^= previous_block[col][row];
            }
        }

        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                previous_block[col][row] = temp[col][row];
            }
        }
    }

    uint8_t n_padding_bytes = blocks[n_blocks - 1][3][3];
    if (n_padding_bytes > 16 || n_padding_bytes == 0) {
        return PADDING_ERROR;
    }

    uint8_t last_block[AES_BLOCK_SIZE];
    uint8_t index = 0;
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            last_block[index] = blocks[n_blocks - 1][col][row];
            index++;
        }
    }

    for (uint8_t i = 0; i < n_padding_bytes; i++) {
        if (last_block[16 - 1 - i] != n_padding_bytes) {
            return PADDING_ERROR;
        }
    }

    uint8_t lenght = AES_BLOCK_SIZE - n_padding_bytes;

    buffer_index = 0;
    for (size_t block = 0; block < n_blocks - 1; block++) {
        for (uint8_t col = 0; col < 4; col++) {
            for (uint8_t row = 0; row < 4; row++) {
                buffer_decrypted[buffer_index] = blocks[block][col][row];
                buffer_index++;
            }
        }
    }

    for (int i = 0; i < lenght; i++) {
        buffer_decrypted[buffer_index] = last_block[i];
        buffer_index++;
    }

    for (size_t block = 0; block < n_blocks; block++) {
        for (uint8_t col = 0; col < 4; col++) {
            free(blocks[block][col]);
        }
        free(blocks[block]);
    }
    free(blocks);

    *size = buffer_index;

    return AES_SUCCESS;
}