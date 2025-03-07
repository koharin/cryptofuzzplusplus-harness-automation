            case    CF_OPERATION("X509_STORE_CTX_verify"):
                {
                    parameters["ntlsa"] = getBuffer(PRNG() % 1024);
                    parameters["ncert"] = getBuffer(PRNG() % 1024);
                    parameters["noncheck"] = getBuffer(PRNG() % 1024);
                    parameters["ntlsa_data"] = getBuffer(PRNG() % 1024);

                    cryptofuzz::operation::X509_STORE_CTX_verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
