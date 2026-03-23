package com.oauth_it.resource;

import com.oauth_it.service.JwtService;
import com.oauth_it.service.TokenStore;
import com.oauth_it.service.UserStore;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Path("/introspect")
@ApplicationScoped
public class IntrospectResource {

    @Inject
    JwtService jwtService;

    @Inject
    TokenStore tokenStore;

    @Inject
    UserStore userStore;

    @ConfigProperty(name = "auth.introspect-secret")
    String introspectSecret;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspect(
            @HeaderParam("X-Introspect-Secret") String providedSecret,
            @FormParam("token") String token) {

        // Constant-time comparison to prevent timing attacks on the shared secret
        if (!secretsMatch(introspectSecret, providedSecret)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "Unauthorized"))
                    .build();
        }

        if (token == null || token.isBlank()) {
            return Response.ok(Map.of("active", false)).build();
        }

        Optional<JWTClaimsSet> claimsOpt = jwtService.verifyJwt(token);
        if (claimsOpt.isEmpty()) {
            return Response.ok(Map.of("active", false)).build();
        }

        JWTClaimsSet claims = claimsOpt.get();
        String jti = claims.getJWTID();

        if (jti == null || !tokenStore.isJwtActive(jti)) {
            return Response.ok(Map.of("active", false)).build();
        }

        String userId = claims.getSubject();
        Map<String, Object> body = new HashMap<>();
        body.put("active", true);
        body.put("userId", userId);
        userStore.findByUserId(userId).ifPresent(u -> body.put("username", u.username));
        return Response.ok(body).build();
    }

    private static boolean secretsMatch(String expected, String provided) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] a = md.digest(expected.getBytes(StandardCharsets.UTF_8));
            byte[] b = md.digest((provided != null ? provided : "").getBytes(StandardCharsets.UTF_8));
            return MessageDigest.isEqual(a, b);
        } catch (Exception e) {
            return false;
        }
    }
}
