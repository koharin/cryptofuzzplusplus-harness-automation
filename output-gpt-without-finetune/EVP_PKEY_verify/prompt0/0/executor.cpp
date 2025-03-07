/* Specialization for EVP_PKEY_verify_Mutation */
template<> void ExecutorBase<bool, EVP_PKEY_verify_Mutation>::postprocess(std::shared_ptr<Module> module, EVP_PKEY_verify_Mutation& mutation, const ExecutorBase<bool, EVP_PKEY_verify_Mutation>::ResultPair& result) const {
    (void)module;
    (void)mutation;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, EVP_PKEY_verify_Mutation>::callModule(std::shared_ptr<Module> module, EVP_PKEY_verify_Mutation& mutation) const {
    
    Datasource ds(mutation.cleartext.GetPtr(), mutation.cleartext.GetSize());

    // Assumed initialization of EVP_PKEY and context
    EVP_PKEY* pkey = InitializePKey(mutation.keySize);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (!ctx || EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return std::nullopt;
    }

    // Set digest type if needed
    if (EVP_PKEY_CTX_set_signature_md(ctx, toEVP_MD(mutation.digestType)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return std::nullopt;
    }

    // Perform verification
    int ret = EVP_PKEY_verify(ctx, ds.GetPtr(), ds.GetSize(), mutation.cleartext.GetPtr(), mutation.cleartext.GetSize());

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Return verification result
    return (ret == 1);
}
