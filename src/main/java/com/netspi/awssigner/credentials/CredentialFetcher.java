package com.netspi.awssigner.credentials;

public interface CredentialFetcher {

    SigningCredentials getCredentials() throws SignerCredentialException;
    
}
