package com.pharma.credentials.models;

public class UserEmail {
    private String username;
    private String email;

    public UserEmail(String username, String email) {
        this.username = username;
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
