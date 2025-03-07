/* Specialization for operation::SMIME_write_ASN1_ex */
template<> void ExecutorBase<component::SMIME_write_ASN1_ex, operation::SMIME_write_ASN1_ex>::postprocess(std::shared_ptr<Module> module, operation::SMIME_write_ASN1_ex& op, const ExecutorBase<component::SMIME_write_ASN1_ex, operation::SMIME_write_ASN1_ex>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::SMIME_write_ASN1_ex> ExecutorBase<component::SMIME_write_ASN1_ex, operation::SMIME_write_ASN1_ex>::callModule(std::shared_ptr<Module> module, operation::SMIME_write_ASN1_ex& op) const {
    RETURN_IF_DISABLED(options.CMS_flags, op.CMS_flag.Get());
    RETURN_IF_DISABLED(options.SMIME_flags, op.SMIME_flag.Get());
    RETURN_IF_DISABLED(options.ciphers, op.cipherType.Get());

    return module->OpSMIME_write_ASN1_ex(op);
}
