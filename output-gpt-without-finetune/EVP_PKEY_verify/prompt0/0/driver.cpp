void Driver::Run(const uint8_t* data, const size_t size) const {
    using fuzzing::datasource::ID;

    static ExecutorEVP_PKEY_verify executorEVP_PKEY_Verify(CF_OPERATION("EVP_PKEY_Verify"), modules, options);

    try {
        Datasource ds(data, size);

        const auto operation = ds.Get<uint64_t>();

        if (!options.operations.Have(operation)) {
            return;
        }

        const auto payload = ds.GetData(0, 1);

        switch (operation) {
            case CF_OPERATION("EVP_PKEY_Verify"):
                executorEVP_PKEY_Verify.Run(ds, payload.data(), payload.size());
                break;
        }
    } catch (Datasource::OutOfData) {
    }
}
