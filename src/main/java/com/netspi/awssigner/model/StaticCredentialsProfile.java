package com.netspi.awssigner.model;

import com.netspi.awssigner.credentials.SignerCredentialException;
import com.netspi.awssigner.credentials.SigningCredentials;
import java.util.Optional;

public class StaticCredentialsProfile extends Profile {

    private String accessKey = null;
    private String secretKey = null;
    private String sessionToken = null;

    public StaticCredentialsProfile(String name) {
        super(name);
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getAccessKey() {
        return Optional.ofNullable(accessKey);
    }

    public void setAccessKey(String accessKey) {
        if (accessKey != null && accessKey.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.accessKey = null;
        } else {
            this.accessKey = accessKey;
        }
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getSecretKey() {
        return Optional.ofNullable(secretKey);
    }

    public void setSecretKey(String secretKey) {
        if (secretKey != null && secretKey.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.secretKey = null;
        } else {
            this.secretKey = secretKey;
        }
    }

    /**
     * If unset, this will return an empty optional, but it should never be an
     * empty/null string.
     */
    public Optional<String> getSessionToken() {
        return Optional.ofNullable(sessionToken);
    }

    public void setSessionToken(String sessionToken) {
        if (sessionToken != null && sessionToken.trim().isEmpty()) {
            //Treat a blank input as null to indicate it's unset.
            this.sessionToken = null;
        } else {
            this.sessionToken = sessionToken;
        }
    }

    @Override
    public boolean requiredFieldsAreSet() {
        return accessKey != null && secretKey != null;
    }

    @Override
    public SigningCredentials getCredentials() throws SignerCredentialException {
        if (accessKey == null && secretKey == null) {
            throw new SignerCredentialException("Access key and secret key are not set for profile: " + getName());
        } else if (accessKey == null) {
            throw new SignerCredentialException("Access key is not set for profile: " + getName());
        } else if (secretKey == null) {
            throw new SignerCredentialException("Secret key is not set for profile: " + getName());
        }

        return new SigningCredentials(accessKey, secretKey, sessionToken);
    }

}
