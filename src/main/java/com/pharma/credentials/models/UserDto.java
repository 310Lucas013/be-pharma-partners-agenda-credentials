package com.pharma.credentials.models;

public class UserDto {
    private String username;
    private String password;
    private boolean using2Fa;
    private String secret;
    private boolean authenticated;

    public UserDto(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public UserDto() {

    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isUsing2Fa() {
        return using2Fa;
    }

    public void setUsing2Fa(boolean using2Fa) {
        this.using2Fa = using2Fa;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    @Override
    public String toString() {
        return "UserDto{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", using2Fa=" + using2Fa +
                ", secret='" + secret + '\'' +
                ", authenticated=" + authenticated +
                '}';
    }
}