/* Specialization for operation::EVP_PKEY_verify */
template<> void ExecutorBase<component::Signature, operation::EVP_PKEY_verify>::postprocess(std::shared_ptr<Module> module, operation::EVP_PKEY_verify& op, const ExecutorBase<component::Signature, operation::EVP_PKEY_verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Signature> ExecutorBase<component::Signature, operation::EVP_PKEY_verify>::callModule(std::shared_ptr<Module> module, operation::EVP_PKEY_verify& op) const {
    RETURN_IF_DISABLED(options.digests, op.digestType.Get());

    if ( op.cleartext.GetSize() == 0 ) {
        return std::nullopt;
    }

    return module->OpEVP_PKEY_verify(op);
}
