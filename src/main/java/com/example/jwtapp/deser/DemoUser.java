package com.example.jwtapp.deser;

import java.io.Serial;
import java.io.Serializable;

public class DemoUser implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private String username;
    private String role;
    private transient String password;
    private String createdAt;

    public DemoUser() {}

    public DemoUser(String username, String role, String password, String createdAt) {
        this.username = username;
        this.role = role;
        this.password = password;
        this.createdAt = createdAt;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getPassword() {
        return password;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "DemoUser{username='" + username + "', role='" + role + "', password=<transient>, createdAt='" + createdAt + "'}";
    }
}
