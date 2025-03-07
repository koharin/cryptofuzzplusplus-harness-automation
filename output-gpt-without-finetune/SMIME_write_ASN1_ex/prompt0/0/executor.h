using ExecutorSMIME_WriteASN1Ex = ExecutorBase<bool, operation::SMIME_WriteASN1Ex>;

class ExecutorSMIME_WriteASN1Ex : public ExecutorBase<bool, operation::SMIME_WriteASN1Ex> {
public:
    bool execute(operation::SMIME_WriteASN1Ex& op) override {
        bool ret = false;

        auto p7 = PKCS7_encrypt(...);  // Assumed to be correctly initialized elsewhere.
        
        // Create a new BIO object to handle the output
        BIO* out = BIO_new_file("smencr.txt", "w");
        if (!out) {
            return false;
        }

        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        
        SMI_ME_EncryptionParams params(ds);
        
        int flags = params.CMS_flag ^ params.SMIME_flag;
        STACK_OF(X509_ALGOR)* mdalgs = NULL;
        
        // Retrieve context from PKCS7 object
        const PKCS7_CTX* ctx = ossl_pkcs7_get0_ctx(p7);
        
        // Determine content type
        int ctype_nid = OBJ_obj2nid(p7->type);
        
        // Handle message digest algorithms for signed data
        if (ctype_nid == NID_pkcs7_signed && p7->d.sign != NULL) {
            mdalgs = p7->d.sign->md_algs;
        }
        
        // Adjust flags for SMIME
        flags ^= SMIME_OLDMIME;
        
        // Call SMIME_write_ASN1_ex to write the encrypted data to the BIO
        ret = SMIME_write_ASN1_ex(out, (ASN1_VALUE*)p7, NULL, flags, ctype_nid,
                                  NID_undef, mdalgs, ASN1_ITEM_rptr(PKCS7),
                                  ossl_pkcs7_ctx_get0_libctx(ctx),
                                  ossl_pkcs7_ctx_get0_propq(ctx));

        BIO_free(out);
        return ret;
    }
};
