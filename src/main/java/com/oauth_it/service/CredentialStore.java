package com.oauth_it.service;

import com.oauth_it.model.StoredCredential;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

@ApplicationScoped
public class CredentialStore implements CredentialRepository {

    @ConfigProperty(name = "auth.credentials-file")
    String credentialsFile;

    private final CopyOnWriteArrayList<StoredCredential> credentials = new CopyOnWriteArrayList<>();

    @PostConstruct
    void load() {
        Path path = Path.of(credentialsFile);
        try {
            Files.createDirectories(path.getParent());
            if (!Files.exists(path)) {
                Files.createFile(path);
                return;
            }
            Files.lines(path)
                    .map(String::trim)
                    .filter(l -> !l.isBlank())
                    .map(StoredCredential::fromLine)
                    .forEach(credentials::add);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load credentials file: " + credentialsFile, e);
        }
    }

    // ------------------------------------------------------------------ //
    // CredentialRepository interface
    // ------------------------------------------------------------------ //

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return credentials.stream()
                .filter(c -> c.username.equals(username))
                .map(c -> PublicKeyCredentialDescriptor.builder()
                        .id(c.credentialId)
                        .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return credentials.stream()
                .filter(c -> c.username.equals(username))
                .map(c -> c.userHandle)
                .findFirst();
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return credentials.stream()
                .filter(c -> c.userHandle.equals(userHandle))
                .map(c -> c.username)
                .findFirst();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return credentials.stream()
                .filter(c -> c.credentialId.equals(credentialId) && c.userHandle.equals(userHandle))
                .map(this::toRegistered)
                .findFirst();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return credentials.stream()
                .filter(c -> c.credentialId.equals(credentialId))
                .map(this::toRegistered)
                .collect(Collectors.toSet());
    }

    // ------------------------------------------------------------------ //
    // Mutation methods
    // ------------------------------------------------------------------ //

    public synchronized void addCredential(StoredCredential cred) {
        credentials.add(cred);
        try {
            Files.writeString(Path.of(credentialsFile),
                    cred.toLine() + System.lineSeparator(),
                    StandardOpenOption.APPEND, StandardOpenOption.CREATE);
        } catch (IOException e) {
            throw new RuntimeException("Failed to append credential", e);
        }
    }

    public synchronized void updateSignCount(ByteArray credentialId, long newCount) {
        for (int i = 0; i < credentials.size(); i++) {
            StoredCredential c = credentials.get(i);
            if (c.credentialId.equals(credentialId)) {
                credentials.set(i, new StoredCredential(
                        c.credentialId, c.userHandle, c.publicKeyCose, newCount, c.username));
                rewriteFile();
                return;
            }
        }
    }

    public boolean hasCredentials(String username) {
        return credentials.stream().anyMatch(c -> c.username.equals(username));
    }

    // ------------------------------------------------------------------ //
    // Private helpers
    // ------------------------------------------------------------------ //

    private RegisteredCredential toRegistered(StoredCredential c) {
        return RegisteredCredential.builder()
                .credentialId(c.credentialId)
                .userHandle(c.userHandle)
                .publicKeyCose(c.publicKeyCose)
                .signatureCount(c.signCount)
                .build();
    }

    private void rewriteFile() {
        List<String> lines = credentials.stream()
                .map(StoredCredential::toLine)
                .toList();
        try {
            Files.write(Path.of(credentialsFile), lines);
        } catch (IOException e) {
            throw new RuntimeException("Failed to rewrite credentials file", e);
        }
    }
}
