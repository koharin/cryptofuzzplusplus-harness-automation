/* Specialization for operation::X509_STORE_CTX_verify */
template<> void ExecutorBase<bool, operation::X509_STORE_CTX_verify>::postprocess(std::shared_ptr<Module> module, operation::X509_STORE_CTX_verify& op, const ExecutorBase<bool, operation::X509_STORE_CTX_verify>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        auto& ntlsa = op.param.ntlsa;
        auto& ncert = op.param.ncert;
        auto& noncheck = op.param.noncheck;

        Pool_X509_STORE_CTX_verify.Set({ntlsa, ncert, noncheck});
    }
}

template<> std::optional<bool> ExecutorBase<bool, operation::X509_STORE_CTX_verify>::callModule(std::shared_ptr<Module> module, operation::X509_STORE_CTX_verify& op) const {
    return module->OpX509_STORE_CTX_verify(op);
}