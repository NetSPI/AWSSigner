package com.netspi.awssigner.credentials;

public class SignerCredentialException extends Exception {

    public SignerCredentialException(String message) {
        super(message);
    }

    public SignerCredentialException(Throwable cause){
        super(cause);
    }
    
    public SignerCredentialException(String message, Throwable cause){
        super(message, cause);
    }
    
    
}
