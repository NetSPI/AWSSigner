package com.netspi.awssigner.signing;

import java.util.Optional;

public enum SigningAlgorithm {
    SIGV4, SIGV4A;
    public static Optional<SigningAlgorithm> fromAuthorizationHeaderString(String authHeaderPartString){
        if(authHeaderPartString.equalsIgnoreCase("AWS4-HMAC-SHA256")){
            return Optional.of(SIGV4);
        } else if(authHeaderPartString.equalsIgnoreCase("AWS4-ECDSA-P256-SHA256")){
            return Optional.of(SIGV4A);
        }  else {
            return Optional.empty();
        }
    }
}
