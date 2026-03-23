package com.oauth_it.resource;

import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Path("/")
@ApplicationScoped
public class SignupResource {

    @Inject
    Template signup;

    @ConfigProperty(name = "auth.base-url")
    String baseUrl;

    @GET
    @Path("/signup")
    @Produces(MediaType.TEXT_HTML)
    public TemplateInstance showSignupForm(@QueryParam("embed") boolean embed) {
        return signup
                .data("error", "")
                .data("username", "")
                .data("baseUrl", baseUrl)
                .data("embed", embed);
    }
}
