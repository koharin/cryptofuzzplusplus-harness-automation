case CF_OPERATION("X509_STORE_CTX_Verify"):
{
    size_t numParts = 0;

    numParts++; // ntlsa
    numParts++; // ncert
    numParts++; // noncheck

    const auto lengths = SplitLength(maxSize - 64, numParts);

    parameters["ntlsa"] = getBuffer(lengths[0]);
    parameters["ncert"] = getBuffer(lengths[1]);
    parameters["noncheck"] = getBuffer(lengths[2]);

    cryptofuzz::operation::X509_STORE_CTX_Verify op(parameters);
    op.Serialize(dsOut2);
}
break;
