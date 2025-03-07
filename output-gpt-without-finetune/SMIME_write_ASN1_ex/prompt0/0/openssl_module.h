#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
    std::optional<int> SMIME_Write_ASN1_Ex(operation::SMIME& op, Datasource& ds) {
        BIO* out = nullptr;
        ASN1_VALUE* val = nullptr;
        BIO* data = nullptr;
        int ctype_nid = NID_undef;
        int econt_nid = NID_undef;
        STACK_OF(X509_ALGOR)* mdalgs = nullptr;
        const ASN1_ITEM* it = nullptr;

        // Extract necessary parameters from operation using Datasource
        try {
            auto CMS_flag = ds.Get<int>();
            auto SMIME_flag = ds.Get<int>();
            auto cipherType = ds.Get<uint64_t>();

            // Implement SMIME_write_ASN1_ex logic based on extracted parameters...
            const EVP_CIPHER* cipher = toEVPCIPHER(static_cast<component::SymmetricCipherType>(cipherType));
            
            // Conditional operations based on the extracted CMS and SMIME flags
            if (CMS_flag > 0 && SMIME_flag > 0) {
                // Example placeholder instance for val
                val = ASN1_VALUE_new();

                CHECK_NULLPTR(val);

                out = BIO_new_file("output.txt", "w");
                CHECK_NULLPTR(out);

                int ret = SMIME_write_ASN1_ex(out, val, data, SMIME_flag | CMS_flag, ctype_nid, econt_nid, mdalgs, it,
                                              ossl_lib_ctx, property_query);
                if (ret != 1) {
                    throw std::runtime_error("SMIME_write_ASN1_ex failed");
                }

                BIO_free(out);
                return ret;
            }

        } catch (const fuzzing::datasource::Datasource::OutOfData&) {
            // Handle extraction errors, if out of data
            return std::nullopt;
        } catch (const std::exception& e) {
            // Handle any other exceptions and clean up
            if (out)
                BIO_free(out);

            if (val)
                ASN1_VALUE_free(val);

            throw; // Re-throw after cleanup
        }

        return std::nullopt;
    }
#endif
