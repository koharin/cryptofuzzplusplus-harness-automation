/* Specialization for operation::X509_STORE_CTX_verify */
template<> void ExecutorBase<int, operation::X509_STORE_CTX_verify>::postprocess(std::shared_ptr<Module> module, operation::X509_STORE_CTX_verify& op, const ExecutorBase<int, operation::X509_STORE_CTX_verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<int> ExecutorBase<int, operation::X509_STORE_CTX_verify>::callModule(std::shared_ptr<Module> module, operation::X509_STORE_CTX_verify>& op) const {
    return module->OpX509_STORE_CTX_verify(op);
}
