package com.oauth_it.resource;

import com.nimbusds.jwt.JWTClaimsSet;
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

import java.util.Map;
import java.util.Optional;

@Path("/token/refresh")
@ApplicationScoped
public class TokenRefreshResource {

    @Inject
    JwtService jwtService;

    @Inject
    TokenStore tokenStore;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response refresh(@FormParam("token") String token) {
        if (token == null || token.isBlank()) {
            return error("invalid_request", "Missing token");
        }

        Optional<JWTClaimsSet> claimsOpt = jwtService.verifyJwt(token);
        if (claimsOpt.isEmpty()) {
            return error("invalid_token", "Token invalid or expired");
        }

        String jti = claimsOpt.get().getJWTID();
        if (jti == null || !tokenStore.isJwtActive(jti)) {
            return error("invalid_token", "Token has been revoked");
        }

        String newToken = jwtService.mintJwt(claimsOpt.get().getSubject());

        return Response.ok(Map.of(
                "access_token", newToken,
                "token_type",   "Bearer",
                "expires_in",   172800
        )).build();
    }

    private Response error(String code, String description) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("error", code, "error_description", description))
                .build();
    }
}
