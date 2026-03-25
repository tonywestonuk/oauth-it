package com.oauth_it.resource;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;

import java.net.URI;

@Path("/logout")
public class LogoutResource {

    @GET
    public Response logout(@Context HttpHeaders headers) {
        // Expire the access_token cookie
        NewCookie cleared = new NewCookie.Builder("access_token")
                .value("")
                .path("/")
                .maxAge(0)
                .build();

        // Redirect back to wherever the user came from, falling back to the origin
        String referer = headers.getHeaderString("Referer");
        String location = (referer != null && !referer.isBlank()) ? referer : "/";

        return Response.seeOther(URI.create(location))
                .cookie(cleared)
                .build();
    }
}
