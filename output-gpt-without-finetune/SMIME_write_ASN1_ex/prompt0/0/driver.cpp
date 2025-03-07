void Driver::Run(const uint8_t* data, const size_t size) const {
    using fuzzing::datasource::ID;

    static ExecutorSMIME_WriteASN1Ex executorSMIME_WriteASN1Ex(CF_OPERATION("SMIME_WriteASN1Ex"), modules, options);

    try {
        Datasource ds(data, size);

        const auto operation = ds.Get<uint64_t>();

        if (!options.operations.Have(operation)) {
            return;
        }

        const auto payload = ds.GetData(0, 1);

        switch (operation) {
            case CF_OPERATION("SMIME_WriteASN1Ex"):
                executorSMIME_WriteASN1Ex.Run(ds, payload.data(), payload.size());
                break;
            // Other operations...
        }
    } catch (Datasource::OutOfData) {}
};
