/* Specialization for operation::SMIME_WriteASN1Ex */
template<> void ExecutorBase<bool, operation::SMIME_WriteASN1Ex>::postprocess(std::shared_ptr<Module> module, operation::SMIME_WriteASN1Ex& op, const ExecutorBase<bool, operation::SMIME_WriteASN1Ex>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::SMIME_WriteASN1Ex>::callModule(std::shared_ptr<Module> module, operation::SMIME_WriteASN1Ex& op) const {
    RETURN_IF_DISABLED(options.ciphers, op.cipherType.Get());

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    
    // Initialize and configure parameters for SMIME operation
    int CMS_flag = ds.Get<int>();
    int SMIME_flag = ds.Get<int>();
    int flags = CMS_flag ^ SMIME_flag;

    // Create and configure BIO
    BIO* out = BIO_new_file("smencr.txt", "w");
    if (!out) return std::nullopt;

    // Assume p7 is the PKCS7 object correctly initialized elsewhere
    PKCS7* p7 = op.getPKCS7(); 
    STACK_OF(X509_ALGOR)* mdalgs = NULL;

    // Get PKCS7 context
    const PKCS7_CTX* ctx = ossl_pkcs7_get0_ctx(p7);
    int ctype_nid = OBJ_obj2nid(p7->type);

    // Handle message digest algorithms for signed data
    if (ctype_nid == NID_pkcs7_signed && p7->d.sign != NULL) {
        mdalgs = p7->d.sign->md_algs;
    }

    // Adjust flags for SMIME
    flags ^= SMIME_OLDMIME;

    // Call SMIME_write_ASN1_ex to write the encrypted data to the BIO
    bool ret = SMIME_write_ASN1_ex(out, (ASN1_VALUE*)p7, NULL, flags, ctype_nid,
                                   NID_undef, mdalgs, ASN1_ITEM_rptr(PKCS7),
                                   ossl_pkcs7_ctx_get0_libctx(ctx),
                                   ossl_pkcs7_ctx_get0_propq(ctx)) == 1;

    BIO_free(out);
    return ret ? std::make_optional(true) : std::nullopt;
}

/* Explicit template instantiation */
template class ExecutorBase<bool, operation::SMIME_WriteASN1Ex>;
