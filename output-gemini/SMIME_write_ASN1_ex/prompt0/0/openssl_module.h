#include <openssl/cms.h>

std::optional<std::vector<uint8_t>>
OpenSSL::SMIME_write_ASN1_ex(const std::vector<uint8_t>& data,
                             const std::vector<uint8_t>& modifier) const
{
    std::optional<std::vector<uint8_t>> rv = std::nullopt;
    Datasource ds(modifier.data(), modifier.size());

    try {
        const auto cmsFlags = ds.Get<uint32_t>();
        const auto smimeFlags = ds.Get<uint32_t>();
        const auto cipherType = ds.Get<uint64_t>();

        (void)cipherType;

        BIO* bioMem = BIO_new(BIO_s_mem());
        BIO* bio = BIO_new(BIO_s_mem());

        if (bioMem == nullptr || bio == nullptr) {
            if (bioMem != nullptr) {
                BIO_free(bioMem);
            }
            if (bio != nullptr) {
                BIO_free(bio);
            }
            goto end;
        }

        {
            const int len = data.size();
            if (BIO_write(bioMem, data.data(), len) != len) {
                goto end;
            }
        }

        {
            BIO* bioData = BIO_new(BIO_s_mem());
            BIO_write(bioData, "test", 4);

            PKCS7* p7 = PKCS7_sign(nullptr, nullptr, nullptr, bioData, PKCS7_BINARY);
            if (p7 == nullptr) {
                BIO_free(bioData);
                goto end;
            }

            int flags = cmsFlags;

            STACK_OF(X509_ALGOR) *mdalgs;
            int ctype_nid = OBJ_obj2nid(p7->type);
            const PKCS7_CTX *ctx = ossl_pkcs7_get0_ctx(p7);

            if (ctype_nid == NID_pkcs7_signed) {
                if (p7->d.sign == NULL)
                    return std::nullopt;
                mdalgs = p7->d.sign->md_algs;
            } else {
                mdalgs = NULL;
            }

            flags ^= SMIME_OLDMIME;

            if(!SMIME_write_ASN1_ex(bio, (ASN1_VALUE *)p7, bioMem, flags, ctype_nid,
                                       NID_undef, mdalgs, ASN1_ITEM_rptr(PKCS7),
                                       ossl_pkcs7_ctx_get0_libctx(ctx),
                                       ossl_pkcs7_ctx_get0_propq(ctx))) {
                PKCS7_free(p7);
                BIO_free(bioData);
                goto end;
            }
            PKCS7_free(p7);
            BIO_free(bioData);
        }

        rv = std::vector<uint8_t>();
        rv->assign(BIO_get_mem_data(bio), BIO_get_mem_data(bio) + BIO_get_mem_size(bio));

    end:
        BIO_free_all(bioMem);
        BIO_free_all(bio);
    } catch (const fuzzing::datasource::Datasource::OutOfData&) {
    }

    return rv;
}
