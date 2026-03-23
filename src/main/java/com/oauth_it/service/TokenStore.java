package com.oauth_it.service;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@ApplicationScoped
public class TokenStore {

    private static final long AUTH_CODE_TTL_MS       = 60_000L;
    private static final long JWT_TTL_MS             = 15 * 60 * 1000L;
    private static final long RECOVERY_TOKEN_TTL_MS  = 15 * 60 * 1000L;
    public  static final long WEBAUTHN_CHALLENGE_TTL_MS = 5 * 60 * 1000L;

    public record AuthCode(String userId, String codeChallenge, long expiryEpochMs) {}
    public record RecoveryToken(String userId, long expiryEpochMs) {}

    public record PendingRegistration(
            String username, String userId,
            PublicKeyCredentialCreationOptions creationOptions,
            long expiryEpochMs,
            boolean isRecovery) {}

    public record PendingAssertion(
            AssertionRequest assertionRequest,
            long expiryEpochMs) {}

    private final ConcurrentHashMap<String, AuthCode>            authCodes            = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String>              activeJwts            = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RecoveryToken>       recoveryTokens        = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, PendingRegistration> pendingRegistrations  = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, PendingAssertion>    pendingAssertions     = new ConcurrentHashMap<>();

    private ScheduledExecutorService scheduler;

    @PostConstruct
    void init() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "token-store-eviction");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::evictExpired, 60, 60, TimeUnit.SECONDS);
    }

    @PreDestroy
    void shutdown() {
        if (scheduler != null) scheduler.shutdownNow();
    }

    // ------------------------------------------------------------------ //
    // Auth Codes
    // ------------------------------------------------------------------ //

    public void storeAuthCode(String code, String userId, String codeChallenge) {
        authCodes.put(code, new AuthCode(userId, codeChallenge, System.currentTimeMillis() + AUTH_CODE_TTL_MS));
    }

    public Optional<AuthCode> consumeAuthCode(String code) {
        AuthCode ac = authCodes.remove(code);
        if (ac == null || System.currentTimeMillis() > ac.expiryEpochMs()) return Optional.empty();
        return Optional.of(ac);
    }

    // ------------------------------------------------------------------ //
    // Active JWTs
    // ------------------------------------------------------------------ //

    public void storeJwt(String jti, String userId) {
        activeJwts.put(jti, userId);
        scheduler.schedule(() -> activeJwts.remove(jti), JWT_TTL_MS, TimeUnit.MILLISECONDS);
    }

    public void revokeJwt(String jti) { activeJwts.remove(jti); }

    public boolean isJwtActive(String jti) { return activeJwts.containsKey(jti); }

    public Optional<String> getUserIdForJwt(String jti) {
        return Optional.ofNullable(activeJwts.get(jti));
    }

    // ------------------------------------------------------------------ //
    // Recovery Tokens
    // ------------------------------------------------------------------ //

    public void storeRecoveryToken(String token, String userId) {
        recoveryTokens.put(token, new RecoveryToken(userId, System.currentTimeMillis() + RECOVERY_TOKEN_TTL_MS));
    }

    public Optional<RecoveryToken> consumeRecoveryToken(String token) {
        RecoveryToken rt = recoveryTokens.remove(token);
        if (rt == null || System.currentTimeMillis() > rt.expiryEpochMs()) return Optional.empty();
        return Optional.of(rt);
    }

    public Optional<RecoveryToken> peekRecoveryToken(String token) {
        RecoveryToken rt = recoveryTokens.get(token);
        if (rt == null) return Optional.empty();
        if (System.currentTimeMillis() > rt.expiryEpochMs()) { recoveryTokens.remove(token); return Optional.empty(); }
        return Optional.of(rt);
    }

    // ------------------------------------------------------------------ //
    // WebAuthn — Pending Registrations
    // ------------------------------------------------------------------ //

    public void storePendingRegistration(String requestId, PendingRegistration reg) {
        pendingRegistrations.put(requestId, reg);
    }

    public Optional<PendingRegistration> consumePendingRegistration(String requestId) {
        PendingRegistration reg = pendingRegistrations.remove(requestId);
        if (reg == null || System.currentTimeMillis() > reg.expiryEpochMs()) return Optional.empty();
        return Optional.of(reg);
    }

    // ------------------------------------------------------------------ //
    // WebAuthn — Pending Assertions
    // ------------------------------------------------------------------ //

    public void storePendingAssertion(String requestId, PendingAssertion pa) {
        pendingAssertions.put(requestId, pa);
    }

    public Optional<PendingAssertion> consumePendingAssertion(String requestId) {
        PendingAssertion pa = pendingAssertions.remove(requestId);
        if (pa == null || System.currentTimeMillis() > pa.expiryEpochMs()) return Optional.empty();
        return Optional.of(pa);
    }

    // ------------------------------------------------------------------ //
    // Eviction
    // ------------------------------------------------------------------ //

    private void evictExpired() {
        long now = System.currentTimeMillis();
        authCodes.entrySet().removeIf(e -> now > e.getValue().expiryEpochMs());
        recoveryTokens.entrySet().removeIf(e -> now > e.getValue().expiryEpochMs());
        pendingRegistrations.entrySet().removeIf(e -> now > e.getValue().expiryEpochMs());
        pendingAssertions.entrySet().removeIf(e -> now > e.getValue().expiryEpochMs());
    }
}
