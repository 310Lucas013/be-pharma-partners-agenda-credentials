package com.pharma.credentials.exeptions;

public class UsernameExistsException extends Throwable {
    public UsernameExistsException(final String message) {
        super(message);
    }
}
