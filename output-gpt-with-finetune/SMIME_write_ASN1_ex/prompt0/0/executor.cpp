/* Specialization for operation::SMIME_write_ASN1_ex */
template<> void ExecutorBase<component::Cleartext, operation::SMIME_write_ASN1_ex>::postprocess(std::shared_ptr<Module> module, operation::SMIME_write_ASN1_ex& op, const ExecutorBase<component::Cleartext, operation::SMIME_write_ASN1_ex>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Cleartext> ExecutorBase<component::Cleartext, operation::SMIME_write_ASN1_ex>::callModule(std::shared_ptr<Module> module, operation::SMIME_write_ASN1_ex& op) const {
    RETURN_IF_DISABLED(options.ciphers, op.cipherType.Get());

    return module->OpSMIME_write_ASN1_ex(op);
}
