    static ExecutorX509_STORE_CTX_verify executorX509_STORE_CTX_verify(CF_OPERATION("X509_STORE_CTX_verify"), modules, options);
    /* ... */
            case CF_OPERATION("X509_STORE_CTX_verify"):
                executorX509_STORE_CTX_verify.Run(ds, payload.data(), payload.size());
                break;
    /* ... */
