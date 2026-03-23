package com.oauth_it.resource;

import com.oauth_it.service.JwtService;
import com.oauth_it.service.TokenStore;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

@Path("/token")
@ApplicationScoped
public class TokenResource {

    @Inject
    TokenStore tokenStore;

    @Inject
    JwtService jwtService;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(
            @FormParam("grant_type") String grantType,
            @FormParam("code") String code,
            @FormParam("code_verifier") String codeVerifier,
            @FormParam("client_id") String clientId,
            @FormParam("redirect_uri") String redirectUri) {

        if (!"authorization_code".equals(grantType)) {
            return errorResponse("unsupported_grant_type", "Only authorization_code grant is supported");
        }

        if (code == null || code.isBlank()) {
            return errorResponse("invalid_request", "Missing code parameter");
        }

        if (codeVerifier == null || codeVerifier.isBlank()) {
            return errorResponse("invalid_request", "Missing code_verifier parameter");
        }

        Optional<TokenStore.AuthCode> authCodeOpt = tokenStore.consumeAuthCode(code);
        if (authCodeOpt.isEmpty()) {
            return errorResponse("invalid_grant", "Auth code not found or expired");
        }

        TokenStore.AuthCode authCode = authCodeOpt.get();

        // Verify PKCE: SHA-256(code_verifier) base64url (no padding) must equal stored codeChallenge
        String computedChallenge = computeCodeChallenge(codeVerifier);
        if (computedChallenge == null || !computedChallenge.equals(authCode.codeChallenge())) {
            return errorResponse("invalid_grant", "PKCE verification failed");
        }

        String jwt = jwtService.mintJwt(authCode.userId());

        Map<String, Object> responseBody = Map.of(
                "access_token", jwt,
                "token_type", "Bearer",
                "expires_in", 900
        );

        return Response.ok(responseBody).build();
    }

    private String computeCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private Response errorResponse(String error, String description) {
        Map<String, String> body = Map.of(
                "error", error,
                "error_description", description
        );
        return Response.status(Response.Status.BAD_REQUEST).entity(body).build();
    }
}
