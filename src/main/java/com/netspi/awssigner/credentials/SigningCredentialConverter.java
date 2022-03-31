package com.netspi.awssigner.credentials;

import java.util.Optional;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

/**
 * Converts from our SigningCredentials type to SDK's AwsCredentials type
 */
public class SigningCredentialConverter implements AwsCredentialsProvider  {

    private final SigningCredentials inputCreds;

    public SigningCredentialConverter(SigningCredentials creds) {
        this.inputCreds = creds;
    }

    @Override
    public AwsCredentials resolveCredentials() {
        final Optional<String> sessionToken = inputCreds.getSessionToken();
        if(sessionToken.isEmpty()){
            return AwsBasicCredentials.create(inputCreds.getAccessKey(), inputCreds.getSecretKey());
        } else {
            return AwsSessionCredentials.create(inputCreds.getAccessKey(), inputCreds.getSecretKey(), sessionToken.get());
        }
    }
    
}
