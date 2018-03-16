#include <src/util/rsa.h>

long long Rsa::RsaModExp(long long b, long long e, long long m) {
    if (b < 0 || e < 0 || m <= 0) {
        exit(1);
    }
    b = b % m;
    if (e == 0) return 1;
    if (e == 1) return b;
    if (e % 2 == 0) {
        return (RsaModExp(b * b % m, e / 2, m) % m);
    }
    if (e % 2 == 1) {
        return (b * RsaModExp(b, (e - 1), m) % m);
    }
}

char *Rsa::RsaDecrypt(const long long *message,
                      const unsigned long message_size,
                      const struct private_key_class *priv) {
    if (message_size % sizeof(long long) != 0) {
        fprintf(stderr,
                "Error: message_size is not divisible by %d, so cannot be "
                "output of rsa_encrypt\n",
                (int)sizeof(long long));
        return NULL;
    }
    // We allocate space to do the decryption (temp) and space for the output as
    // a char array (decrypted)
    char *decrypted = malloc(message_size / sizeof(long long));
    char *temp = malloc(message_size);
    if ((decrypted == NULL) || (temp == NULL)) {
        fprintf(stderr, "Error: Heap allocation failed.\n");
        return NULL;
    }
    // Now we go through each 8-byte chunk and decrypt it.
    long long i = 0;
    for (int i = 0; i < message_size / 8; i++) {
        temp[i] = RsaModExp(message[i], priv->exponent, priv->modulus);
    }
    // The result should be a number in the char range, which gives back the
    // original byte. We put that into decrypted, then return.
    for (int i = 0; i < message_size / 8; i++) {
        decrypted[i] = temp[i];
    }
    free(temp);
    return decrypted;
}
