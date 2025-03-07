void test(const operation::SMIME_write_ASN1_ex& op, const std::optional<component::SMIME_write_ASN1_ex_Result>& result) {
    using fuzzing::datasource::ID;
    if (result == std::nullopt) {
        return;
    }
    
    // Example assertion: check if the output length is not unreasonable
    if (result->output.GetSize() > 1024 * 1024) { // 1 MB
        abort();
    }

    // You can add more test cases based on the mutation variables: CMS_flag, SMIME_flag, cipherType
    // For example, check for specific flags and cipher combinations:
    if (op.flags & CMS_DETACHED && op.flags & CMS_STREAM && op.cipherType.Get() == ID("DES-CBC")) {
        // Add specific assertions for this combination
        // For instance, verify the content is empty and the output is in DER format
        if (!result->content.IsEmpty()) {
            abort();
        }
        // ... more checks ...
    }
}
