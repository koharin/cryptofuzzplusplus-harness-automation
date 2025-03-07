/* Specialization for operation::EVP_PKEY_verify */
template<> void ExecutorBase<bool, operation::EVP_PKEY_verify>::postprocess(std::shared_ptr<Module> module, operation::EVP_PKEY_verify& op, const ExecutorBase<bool, operation::EVP_PKEY_verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::EVP_PKEY_verify>::callModule(std::shared_ptr<Module> module, operation::EVP_PKEY_verify& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    const size_t keySize = op.cleartext.GetSize();
    if ( keySize == 0 || keySize > 4096 ) {
        return std::nullopt;
    }

    return module->OpEVP_PKEY_verify(op);
}
