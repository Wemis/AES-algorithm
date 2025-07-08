Author: Danylo Derkach

## Usage example
```C
#include <stdio.h>
#include <stdint.h>
#include "headers/aes.h"


int main() {
    char* plaintext = "Hello, world!";
    int cipher_size;
    int lenght;

    uint8_t key[16] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76};
    uint8_t iv[16] = {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0};

    uint8_t encrypted[65];
    uint8_t decrypted[65];

    AES_128_CBC_encrypt(key, iv, (const unsigned char*)plaintext, 13, encrypted, &cipher_size);
    AES_128_CBC_decrypt(key, iv, encrypted, cipher_size, decrypted, &lenght);

    for (int i = 0; i < cipher_size; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    decrypted[lenght] = '\0';
    printf("%s\n", decrypted);
}
