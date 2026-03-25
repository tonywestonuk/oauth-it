package com.oauth_it.resource;

import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Path("/authorize")
@ApplicationScoped
public class AuthorizeResource {

    @Inject
    Template login;

    @ConfigProperty(name = "auth.clients")
    String clientsConfig;

    @ConfigProperty(name = "auth.base-url")
    String baseUrl;

    private final Map<String, Set<String>> allowedClients = new HashMap<>();

    @PostConstruct
    void init() {
        if (clientsConfig == null || clientsConfig.isBlank()) return;
        Arrays.stream(clientsConfig.split(","))
                .map(String::trim)
                .filter(e -> e.contains(":"))
                .forEach(e -> {
                    int idx = e.indexOf(':');
                    allowedClients.computeIfAbsent(e.substring(0, idx).trim(), k -> new HashSet<>())
                                  .add(e.substring(idx + 1).trim());
                });
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response showLoginForm(
            @QueryParam("client_id") String clientId,
            @QueryParam("redirect_uri") String redirectUri,
            @QueryParam("code_challenge") String codeChallenge,
            @QueryParam("code_challenge_method") String codeChallengeMethod,
            @QueryParam("state") String state,
            @QueryParam("embed") boolean embed) {

        if (!isValidClient(clientId, redirectUri)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid client_id or redirect_uri")
                    .type(MediaType.TEXT_PLAIN).build();
        }

        if (!"S256".equals(codeChallengeMethod)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Only code_challenge_method=S256 is supported")
                    .type(MediaType.TEXT_PLAIN).build();
        }

        TemplateInstance instance = login
                .data("clientId", clientId)
                .data("redirectUri", redirectUri)
                .data("codeChallenge", codeChallenge)
                .data("codeChallengeMethod", codeChallengeMethod)
                .data("state", state != null ? state : "")
                .data("error", "")
                .data("baseUrl", baseUrl)
                .data("embed", embed);

        return Response.ok(instance).build();
    }

    public boolean isValidClient(String clientId, String redirectUri) {
        if (clientId == null || redirectUri == null) return false;
        Set<String> uris = allowedClients.get(clientId);
        return uris != null && uris.contains(redirectUri);
    }
}
