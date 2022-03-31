package com.netspi.awssigner.signing;

public class SigningException extends Exception {

    public SigningException(String message) {
        super(message);
    }

    public SigningException(Throwable cause) {
        super(cause);
    }

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }

}
