package com.netspi.awssigner.signing;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public interface AwsRequestSigner {

    public byte[] sign(IHttpRequestResponse messageInfo, IRequestInfo request, ParsedAuthHeader authHeader) throws SigningException;

}
