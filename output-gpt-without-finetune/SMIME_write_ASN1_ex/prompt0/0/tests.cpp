void test(const operation::SMIME_write_ASN1_ex& op, const std::optional<bool>& result) {
    if (!result) {
        std::cerr << "SMIME_write_ASN1_ex operation failed\n";
        return;
    }

    // Test for flag consistency, ensuring that special cases like CMS_STREAM are handled correctly
    if (op.flags & CMS_flag::CMS_STREAM) {
        if (!(op.flags & SMIME_flag::SMIME_OLDMIME)) {
            std::cerr << "CMS_STREAM flag set without SMIME_OLDMIME flag\n";
            abort();
        }
    }

    // Check for correct cipher type handling
    if (op.cipherType == CipherType::Unsupported) {
        std::cerr << "Attempt to use unsupported cipher type\n";
        abort();
    }

    // Additional tests can be added here as needed for specific SMIME behavior
}
