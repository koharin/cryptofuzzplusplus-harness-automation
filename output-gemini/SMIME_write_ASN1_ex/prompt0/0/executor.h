/* Declare aliases */
using ExecutorSMIME_write_ASN1_ex = ExecutorBase<SMIME_write_ASN1_ex, SMIME_write_ASN1_ex>;

template <>
class Executor<SMIME_write_ASN1_ex, SMIME_write_ASN1_ex> : public ExecutorBase<SMIME_write_ASN1_ex, SMIME_write_ASN1_ex> {
    public:
        Executor(const std::string& name) : ExecutorBase<SMIME_write_ASN1_ex, SMIME_write_ASN1_ex>(name) {}

    protected:
        std::optional<SMIME_write_ASN1_ex> Execute(const SMIME_write_ASN1_ex& input) override {
            (void)input;
            return std::nullopt;
        }

        std::optional<SMIME_write_ASN1_ex> Execute(const SMIME_write_ASN1_ex_Pair& pair) override {
            try {
                Datasource ds(pair.modifier.first.GetPtr(), pair.modifier.first.GetSize());
                return SMIME_write_ASN1_ex(ds);
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            return std::nullopt;
        }

        bool Compare(const std::optional<SMIME_write_ASN1_ex>& left, const std::optional<SMIME_write_ASN1_ex>& right) override {
            (void)left;
            (void)right;
            return true;
        }

        void PostProcess(const SMIME_write_ASN1_ex& input, const std::optional<SMIME_write_ASN1_ex>& result) override {
            (void)result;
            Datasource ds(input.modifier.second.GetPtr(), input.modifier.second.GetSize());
            (void)ds;
        }
};

