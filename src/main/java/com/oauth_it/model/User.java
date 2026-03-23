package com.oauth_it.model;

public class User {
    public final String username;
    public final String userId;

    public User(String username, String userId) {
        this.username = username;
        this.userId   = userId;
    }

    public String toLine() {
        return username + ":" + userId;
    }

    public static User fromLine(String line) {
        String[] p = line.split(":", 2);
        return new User(p[0], p[1]);
    }
}
