package com.oauth_it.resource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.oauth_it.model.StoredCredential;
import com.oauth_it.model.User;
import com.oauth_it.service.CredentialStore;
import com.oauth_it.service.SecurityUtils;
import com.oauth_it.service.TokenStore;
import com.oauth_it.service.UserStore;
import com.oauth_it.service.WebAuthnService;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Path("/webauthn")
@ApplicationScoped
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class WebAuthnResource {

    private static final Logger log = Logger.getLogger(WebAuthnResource.class);

    private static final int USER_ID_LENGTH  = 8;
    private static final int REQUEST_ID_SIZE = 16; // bytes → 32 hex chars

    @Inject WebAuthnService webAuthnService;
    @Inject UserStore userStore;
    @Inject CredentialStore credentialStore;
    @Inject TokenStore tokenStore;
    @Inject ObjectMapper mapper;

    // ------------------------------------------------------------------ //
    // Registration
    // ------------------------------------------------------------------ //

    @POST
    @Path("/register/start")
    public Response registerStart(RegisterStartRequest req) {
        if (req.username == null || req.username.isBlank())
            return error("Username is required.");

        String username = req.username.trim();

        if (!username.matches("[A-Za-z0-9_-]{3,32}"))
            return error("Username must be 3–32 characters: letters, digits, _ or -");
        if (userStore.findByUsername(username).isPresent())
            return error("That username is already taken.");

        String userId = SecurityUtils.randomAlphanumeric(USER_ID_LENGTH);
        PublicKeyCredentialCreationOptions options = webAuthnService.startRegistration(username, userId);

        String requestId = SecurityUtils.randomHex(REQUEST_ID_SIZE);
        long expiry = System.currentTimeMillis() + TokenStore.WEBAUTHN_CHALLENGE_TTL_MS;
        tokenStore.storePendingRegistration(requestId,
                new TokenStore.PendingRegistration(username, userId, options, expiry, false));

        try {
            ObjectNode resp = mapper.createObjectNode();
            resp.put("requestId", requestId);
            resp.put("creationOptions", options.toCredentialsCreateJson());
            return Response.ok(resp).build();
        } catch (Exception e) {
            log.error("Failed to serialise registration options", e);
            return error("Failed to generate registration options.");
        }
    }

    @POST
    @Path("/register/finish")
    public Response registerFinish(RegisterFinishRequest req) {
        if (req.requestId == null || req.credential == null)
            return error("Missing requestId or credential.");

        Optional<TokenStore.PendingRegistration> pendingOpt =
                tokenStore.consumePendingRegistration(req.requestId);
        if (pendingOpt.isEmpty())
            return error("Registration session expired or not found. Please try again.");

        TokenStore.PendingRegistration pending = pendingOpt.get();

        RegistrationResult result;
        try {
            result = webAuthnService.finishRegistration(pending.creationOptions(), req.credential);
        } catch (Exception e) {
            log.warnf(e, "Passkey registration failed for user %s", pending.username());
            return error("Passkey registration failed. Please try again.");
        }

        ByteArray userHandle = new ByteArray(pending.userId().getBytes(StandardCharsets.UTF_8));

        StoredCredential cred = new StoredCredential(
                result.getKeyId().getId(),
                userHandle,
                result.getPublicKeyCose(),
                result.getSignatureCount(),
                pending.username());

        credentialStore.addCredential(cred);
        if (!pending.isRecovery()) {
            userStore.addUser(new User(pending.username(), pending.userId()));
        }

        return Response.ok("{\"ok\":true}").build();
    }

    // ------------------------------------------------------------------ //
    // Passkey Recovery (re-register after device loss)
    // ------------------------------------------------------------------ //

    @POST
    @Path("/recover/start")
    public Response recoverStart(RecoverStartRequest req) {
        if (req.recoveryToken == null || req.recoveryToken.isBlank())
            return error("Missing recovery token.");

        Optional<TokenStore.RecoveryToken> tokenOpt = tokenStore.consumeRecoveryToken(req.recoveryToken);
        if (tokenOpt.isEmpty())
            return error("Recovery link has expired or is invalid. Please request a new one.");

        Optional<User> userOpt = userStore.findByUserId(tokenOpt.get().userId());
        if (userOpt.isEmpty())
            return error("Account not found.");

        User user = userOpt.get();
        PublicKeyCredentialCreationOptions options = webAuthnService.startRegistration(user.username, user.userId);

        String requestId = SecurityUtils.randomHex(REQUEST_ID_SIZE);
        long expiry = System.currentTimeMillis() + TokenStore.WEBAUTHN_CHALLENGE_TTL_MS;
        tokenStore.storePendingRegistration(requestId,
                new TokenStore.PendingRegistration(user.username, user.userId, options, expiry, true));

        try {
            ObjectNode resp = mapper.createObjectNode();
            resp.put("requestId", requestId);
            resp.put("creationOptions", options.toCredentialsCreateJson());
            return Response.ok(resp).build();
        } catch (Exception e) {
            log.error("Failed to serialise recovery options", e);
            return error("Failed to generate recovery options.");
        }
    }

    // ------------------------------------------------------------------ //
    // Authentication
    // ------------------------------------------------------------------ //

    @POST
    @Path("/auth/start")
    public Response authStart(AuthStartRequest req) {
        if (req.username == null || req.username.isBlank())
            return error("Username is required.");

        String username = req.username.trim();

        // Return the same message for both "unknown user" and "no passkey" to
        // avoid leaking which usernames are registered (user enumeration).
        if (userStore.findByUsername(username).isEmpty() || !credentialStore.hasCredentials(username))
            return error("No passkey found for that username.");

        com.yubico.webauthn.AssertionRequest assertionRequest =
                webAuthnService.startAssertion(username);

        String requestId = SecurityUtils.randomHex(REQUEST_ID_SIZE);
        long expiry = System.currentTimeMillis() + TokenStore.WEBAUTHN_CHALLENGE_TTL_MS;
        tokenStore.storePendingAssertion(requestId,
                new TokenStore.PendingAssertion(assertionRequest, expiry));

        try {
            ObjectNode resp = mapper.createObjectNode();
            resp.put("requestId", requestId);
            resp.put("requestOptions", assertionRequest.toCredentialsGetJson());
            return Response.ok(resp).build();
        } catch (Exception e) {
            log.error("Failed to serialise authentication options", e);
            return error("Failed to generate authentication options.");
        }
    }

    @POST
    @Path("/auth/finish")
    public Response authFinish(AuthFinishRequest req) {
        if (req.requestId == null || req.assertion == null)
            return error("Missing requestId or assertion.");

        Optional<TokenStore.PendingAssertion> pendingOpt =
                tokenStore.consumePendingAssertion(req.requestId);
        if (pendingOpt.isEmpty())
            return error("Authentication session expired. Please try again.");

        AssertionResult result;
        try {
            result = webAuthnService.finishAssertion(
                    pendingOpt.get().assertionRequest(), req.assertion);
        } catch (Exception e) {
            log.warn("Passkey assertion failed", e);
            return error("Passkey verification failed.");
        }

        if (!result.isSuccess())
            return error("Authentication failed.");

        credentialStore.updateSignCount(result.getCredentialId(), result.getSignatureCount());

        String userId = new String(result.getUserHandle().getBytes(), StandardCharsets.UTF_8);

        String code = SecurityUtils.randomHex(32);
        tokenStore.storeAuthCode(code, userId, req.codeChallenge != null ? req.codeChallenge : "");

        ObjectNode resp = mapper.createObjectNode();
        resp.put("code", code);
        resp.put("state", req.state != null ? req.state : "");
        return Response.ok(resp).build();
    }

    // ------------------------------------------------------------------ //
    // Request / response POJOs
    // ------------------------------------------------------------------ //

    public static class RegisterStartRequest {
        public String username;
    }

    public static class RegisterFinishRequest {
        public String requestId;
        public String credential;
    }

    public static class AuthStartRequest {
        public String username;
    }

    public static class RecoverStartRequest {
        public String recoveryToken;
    }

    public static class AuthFinishRequest {
        public String requestId;
        public String assertion;
        public String codeChallenge;
        public String clientId;
        public String redirectUri;
        public String state;
    }

    // ------------------------------------------------------------------ //
    // Helpers
    // ------------------------------------------------------------------ //

    private Response error(String msg) {
        ObjectNode node = mapper.createObjectNode();
        node.put("error", msg);
        return Response.ok(node).build();
    }
}
