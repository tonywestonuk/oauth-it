package com.oauth_it.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

/**
 * Calls the game server to validate that an email address belongs to a known user.
 *
 * Expected game-server endpoint:
 *   POST {auth.game-server.url}/auth/validate-email
 *   Header: X-Auth-Secret: {auth.game-server.secret}
 *   Body:   {"email":"user@example.com"}
 *   200 OK: {"userId":"abc123","email":"user@example.com"}
 *   non-200: email not found
 *
 * Omit auth.game-server.url in application.properties to disable recovery entirely.
 */
@ApplicationScoped
public class GameServerClient {

    private static final Logger log = Logger.getLogger(GameServerClient.class);

    @ConfigProperty(name = "auth.game-server.url")
    java.util.Optional<String> gameServerUrl;

    @ConfigProperty(name = "auth.game-server.secret")
    java.util.Optional<String> gameServerSecret;

    @Inject
    ObjectMapper mapper;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /**
     * Returns the userId associated with the given email, or empty if not found
     * or the game server is not configured.
     */
    public Optional<String> findUserIdByEmail(String email) {
        if (gameServerUrl.isEmpty()) return Optional.empty();

        try {
            String body = mapper.writeValueAsString(mapper.createObjectNode().put("email", email));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(gameServerUrl.get().stripTrailing() + "/auth/validate-email"))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .header("X-Auth-Secret", gameServerSecret.orElse(""))
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) return Optional.empty();

            JsonNode json = mapper.readTree(response.body());
            JsonNode userIdNode = json.get("userId");
            if (userIdNode == null || userIdNode.isNull()) return Optional.empty();
            return Optional.of(userIdNode.asText());

        } catch (Exception e) {
            log.warnf(e, "Game server email validation failed for request");
            return Optional.empty();
        }
    }
}
