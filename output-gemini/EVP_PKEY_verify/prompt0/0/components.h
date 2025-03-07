#include "cryptofuzz/components.h"
#include "cryptofuzz/operations.h"
#include "cryptofuzz/util.h"
#include "cryptofuzz/cryptofuzz.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    CF_ASSERT_GREATER(size, 0);
    Datasource ds(data, size);
    std::optional<component::Signature> result;

    try {
        auto x = ds.Get<EVP_PKEY_verify_Pair>();

        /* Assuming you have a function to convert uint64_t to EVP_MD* */
        const EVP_MD* md = toEVPMD(x.digestType);

        /* Assuming you have a mechanism to get a private key based on keySize */
        auto pkey = getPrivateKey(x.keySize);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx) {
            return 0;
        }
        if (EVP_PKEY_sign_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
        if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }

        size_t siglen;
        if (EVP_PKEY_sign(ctx, NULL, &siglen, (const unsigned char*)x.cleartext.data(), x.cleartext.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }

        std::vector<uint8_t> signature(siglen);
        if (EVP_PKEY_sign(ctx, signature.data(), &siglen, (const unsigned char*)x.cleartext.data(), x.cleartext.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }

        result = component::Signature(signature.data(), siglen);
        EVP_PKEY_CTX_free(ctx);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    return 0;
}
