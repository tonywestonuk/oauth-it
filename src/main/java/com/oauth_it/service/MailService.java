package com.oauth_it.service;

import io.quarkus.mailer.Mail;
import io.quarkus.mailer.Mailer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class MailService {

    @Inject
    Mailer mailer;

    @ConfigProperty(name = "auth.base-url")
    String baseUrl;

    public void sendPasskeyRecoveryEmail(String to, String token) {
        String recoveryUrl = baseUrl + "/recover-passkey/verify?token=" + token;
        String html = """
                <!DOCTYPE html><html><body>
                  <h2>Passkey Recovery</h2>
                  <p>We received a request to register a new passkey for your account.</p>
                  <p><a href="%s">Register new passkey</a></p>
                  <p>This link expires in 15 minutes.</p>
                  <p>If you did not request this, please ignore this email.</p>
                </body></html>
                """.formatted(recoveryUrl);

        mailer.send(Mail.withHtml(to, "Register a new passkey", html));
    }
}
