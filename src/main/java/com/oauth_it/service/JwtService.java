package com.oauth_it.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class JwtService {

    private static final long JWT_TTL_MS = 48 * 60 * 60 * 1000L; // 48 hours

    @ConfigProperty(name = "auth.jwt.secret")
    String secret;

    @Inject
    TokenStore tokenStore;

    private byte[] secretBytes;

    @PostConstruct
    void init() {
        secretBytes = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (secretBytes.length < 32) {
            throw new IllegalStateException("auth.jwt.secret must be at least 32 bytes");
        }
    }

    /**
     * Mints a signed HS256 JWT for the given userId.
     * Also registers the jti in the TokenStore.
     */
    public String mintJwt(String userId) {
        try {
            String jti = UUID.randomUUID().toString();
            long nowMs = System.currentTimeMillis();
            Date iat = new Date(nowMs);
            Date exp = new Date(nowMs + JWT_TTL_MS);

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(userId)
                    .jwtID(jti)
                    .issueTime(iat)
                    .expirationTime(exp)
                    .build();

            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            SignedJWT signedJWT = new SignedJWT(header, claims);

            JWSSigner signer = new MACSigner(secretBytes);
            signedJWT.sign(signer);

            tokenStore.storeJwt(jti, userId);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to mint JWT", e);
        }
    }

    /**
     * Verifies the JWT signature and expiry.
     * Returns the claims if valid, empty otherwise.
     */
    public Optional<JWTClaimsSet> verifyJwt(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(secretBytes);

            if (!signedJWT.verify(verifier)) {
                return Optional.empty();
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp == null || exp.before(new Date())) {
                return Optional.empty();
            }

            return Optional.of(claims);
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }
}
