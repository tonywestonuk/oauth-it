package com.oauth_it.resource;

import com.oauth_it.model.User;
import com.oauth_it.service.AppServerClient;
import com.oauth_it.service.MailService;
import com.oauth_it.service.SecurityUtils;
import com.oauth_it.service.TokenStore;
import com.oauth_it.service.UserStore;
import org.jboss.logging.Logger;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Optional;

/**
 * Passkey recovery flow.
 *
 * GET  /recover-passkey          — email form
 * POST /recover-passkey          — validate email via app server, send recovery link
 * GET  /recover-passkey/verify   — landing page before WebAuthn re-registration
 */
@Path("/")
@ApplicationScoped
public class PasswordResetResource {

    @Inject Template forgot;
    @Inject Template reset;
    @Inject Template message;

    @Inject UserStore userStore;
    @Inject TokenStore tokenStore;
    @Inject MailService mailService;
    @Inject AppServerClient appServerClient;

    private static final Logger log = Logger.getLogger(PasswordResetResource.class);

    @ConfigProperty(name = "auth.base-url")
    String baseUrl;

    @ConfigProperty(name = "auth.app-server.url")
    java.util.Optional<String> appServerUrl;

    private static final String SENT_MSG =
            "If that email address is registered with your account, you'll receive a recovery link shortly. "
            + "The link expires in 15 minutes.";

    @GET
    @Path("/recover-passkey")
    @Produces(MediaType.TEXT_HTML)
    public TemplateInstance showRecoveryForm() {
        return forgot.data("error", "").data("baseUrl", baseUrl);
    }

    @POST
    @Path("/recover-passkey")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response processRecovery(@FormParam("email") String email) {
        if (appServerUrl.isEmpty()) {
            return Response.ok(message
                    .data("title", "Recovery Unavailable")
                    .data("body", "Passkey recovery is not configured on this server. Please contact support.")
                    .data("baseUrl", baseUrl)
                    .data("embed", false))
                    .build();
        }

        if (email != null && !email.isBlank()) {
            final String trimmedEmail = email.trim();
            appServerClient.findUserIdByEmail(trimmedEmail)
                    .flatMap(userStore::findByUserId)
                    .ifPresent(user -> {
                        String token = SecurityUtils.randomHex(32);
                        tokenStore.storeRecoveryToken(token, user.userId);
                        try {
                            mailService.sendPasskeyRecoveryEmail(trimmedEmail, token);
                        } catch (Exception e) {
                            log.warnf(e, "Failed to send passkey recovery email (token still valid)");
                        }
                    });
        }

        return Response.ok(message
                .data("title", "Recovery Email Sent")
                .data("body", SENT_MSG)
                .data("baseUrl", baseUrl)
                .data("embed", false))
                .build();
    }

    @GET
    @Path("/recover-passkey/verify")
    @Produces(MediaType.TEXT_HTML)
    public Response showRecoveryPage(@QueryParam("token") String token) {
        if (token == null || token.isBlank()) {
            return Response.ok(message
                    .data("title", "Invalid Link")
                    .data("body", "The recovery link is missing or invalid.")
                    .data("baseUrl", baseUrl)
                    .data("embed", false))
                    .build();
        }

        if (tokenStore.peekRecoveryToken(token).isEmpty()) {
            return Response.ok(message
                    .data("title", "Link Expired or Invalid")
                    .data("body", "The recovery link has expired or is invalid. Please request a new one.")
                    .data("baseUrl", baseUrl)
                    .data("embed", false))
                    .build();
        }

        return Response.ok(reset
                .data("recoveryToken", token)
                .data("baseUrl", baseUrl))
                .build();
    }

}
