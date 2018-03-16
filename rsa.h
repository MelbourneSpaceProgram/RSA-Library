#ifndef SRC_UTIL_RSA_H_
#define SRC_UTIL_RSA_H_

class Rsa {
    typedef struct PublicKey {
        long long modulus_;
        long long exponent_;
    } PublicKey;

   public:
    static char *RsaDecrypt(const long long *message,
                            const unsigned long message_size,
                            const PublicKey *priv);

   private:
    static long long RsaModExp(long long b, long long e, long long m);
};

#endif  // SRC_UTIL_RSA_H_
