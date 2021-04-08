package com.pharma.credentials.exeptions;

public class UsernameExistsException extends RuntimeException  {
    public UsernameExistsException(String s) {
        super(s);
    }
}
