#include "mcrypt.h"

#include <stdio.h>

int main(void)
{
    uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE];
    mcrypt_status_t status = mcrypt_sha256("abc", 3u, digest);
    if (status != MCRYPT_OK) {
        return 1;
    }
    printf("%02x%02x%02x%02x\n", digest[0], digest[1], digest[2], digest[3]);
    return 0;
}
