package com.pharma.credentials.models;

public class CodeVerifyRequest {
    private String username;
    private String code;

    //default constructor for JSON Parsing
    public CodeVerifyRequest()
    {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
