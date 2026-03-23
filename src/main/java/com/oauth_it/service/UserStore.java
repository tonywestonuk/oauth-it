package com.oauth_it.service;

import com.oauth_it.model.User;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class UserStore {

    @ConfigProperty(name = "auth.users-file")
    String usersFile;

    private final ConcurrentHashMap<String, User> usersByUsername = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, User> usersByUserId   = new ConcurrentHashMap<>();

    @PostConstruct
    void load() {
        Path path = Path.of(usersFile);
        try {
            Files.createDirectories(path.getParent());
            if (!Files.exists(path)) {
                Files.createFile(path);
                return;
            }
            Files.lines(path)
                    .map(String::trim)
                    .filter(l -> !l.isBlank())
                    .map(User::fromLine)
                    .forEach(u -> { usersByUsername.put(u.username, u); usersByUserId.put(u.userId, u); });
        } catch (IOException e) {
            throw new RuntimeException("Failed to load users file: " + usersFile, e);
        }
    }

    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(usersByUsername.get(username));
    }

    public Optional<User> findByUserId(String userId) {
        return Optional.ofNullable(usersByUserId.get(userId));
    }

    public synchronized void addUser(User user) {
        usersByUsername.put(user.username, user);
        usersByUserId.put(user.userId, user);
        try {
            Files.writeString(Path.of(usersFile),
                    user.toLine() + System.lineSeparator(),
                    StandardOpenOption.APPEND, StandardOpenOption.CREATE);
        } catch (IOException e) {
            throw new RuntimeException("Failed to append user", e);
        }
    }
}
