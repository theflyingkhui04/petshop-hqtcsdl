package com.BTL_LTW.JanyPet.dto.request;

import com.fasterxml.jackson.annotation.JsonAlias;

public class LoginRequest {
    // Cho phép map từ key "user" hoặc "username" sang biến này
    @JsonAlias({"user", "username"})
    private String username;
    private String password;

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
}
