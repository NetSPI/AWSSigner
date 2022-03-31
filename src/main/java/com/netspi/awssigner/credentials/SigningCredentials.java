
package com.netspi.awssigner.credentials;

import java.util.Optional;


public class SigningCredentials {

    private final String accessKey;
    private final String secretKey;
    private final String sessionToken;

    public SigningCredentials(String accessKey, String secretKey, String sessionToken) {
        if(accessKey == null || accessKey.trim().isEmpty()){
            throw new IllegalArgumentException("Access Key may not be null or blank");
        }
        this.accessKey = accessKey;
        
        if(secretKey == null || secretKey.trim().isEmpty()){
            throw new IllegalArgumentException("Secret Key may not be null or blank");
        }
        this.secretKey = secretKey;
        
        this.sessionToken = sessionToken;
        
    }
    
    public String getAccessKey() {
        return accessKey;
    }
    
    public String getSecretKey() {
        return secretKey;
    }
    
    public Optional<String> getSessionToken() {
        if(sessionToken==null|| sessionToken.trim().isEmpty()){
            return Optional.empty();
        } else {
            return Optional.of(sessionToken);
        }
    }
    
}
