# oauth-it — Setup Guide for Quarkus Clients

oauth-it is a lightweight OAuth2 authorisation server with WebAuthn/passkey support,
built on Quarkus. This guide covers deploying it behind NGINX and wiring up a Quarkus
client application.

---

## How application.properties Works (Dev vs Production)

### Dev mode (current setup on server)
oauth-it is started with `mvn quarkus:dev` from the source directory. Quarkus reads
`src/main/resources/application.properties` directly and hot-reloads it on change.
No JAR build is needed — edit the file and changes apply immediately.

### Production (built JAR)
When deployed as a JAR, Quarkus is started with:
```
-Dquarkus.config.locations=/usr/local/oauth-it-app/application.properties
```
This external file **overrides** the bundled `application.properties` inside the JAR.
Only properties present in the external file are overridden; everything else falls back
to the bundled defaults. This is the same mechanism used by the `backgammon` and
`backgammon-test` services via their init.d scripts.

Sensitive values should be supplied via environment variables rather than committed:
```properties
auth.jwt.secret=${JWT_SECRET:change-me-in-production}
auth.introspect-secret=${INTROSPECT_SECRET:change-me-introspect-secret}
```

---

## NGINX Configuration

oauth-it runs on port 7181 with root path `/auth`. NGINX proxies public traffic to it.

### Proxy block (add to each server block that needs auth)
```nginx
location /auth/ {
    proxy_pass         http://127.0.0.1:7181;
    proxy_http_version 1.1;

    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;

    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
}
```

Add this block to every subdomain's NGINX server block that needs passkey sign-in.

### WebAuthn .well-known endpoint
If your WebAuthn RP ID (`auth.rp.id`) is a parent domain of the origins users visit
(e.g. RP ID is `gammonstreak.com` but users visit `www.gammonstreak.com`), browsers
fetch `https://<rp-id>/.well-known/webauthn` to verify the delegation. Add this to
the **root domain** server block:

```nginx
location = /.well-known/webauthn {
    add_header Content-Type application/json;
    return 200 '{"origins":["https://www.example.com","https://example.com","https://test.example.com"]}';
}
```

This is not needed if the RP ID exactly matches the origin (e.g. both are `www.example.com`).

---

## oauth-it application.properties

Key settings to configure for your deployment:

```properties
# Port and root path — must match NGINX proxy_pass target and location prefix
quarkus.http.port=7181
quarkus.http.root-path=/auth

# JWT signing secret — change in production, minimum 32 characters
auth.jwt.secret=change-me-in-production-must-be-at-least-32-chars

# Allowed OAuth clients — format: client_id:redirect_uri (comma-separated)
# Add both with and without trailing slash to handle browser differences
auth.clients=myclient:http://localhost:8080/,myclient:https://www.example.com/,myclient:https://www.example.com

# Shared secret for /introspect calls — must match the client server config
auth.introspect-secret=change-me-introspect-secret

# WebAuthn Relying Party
# rp.id must be the domain (or a parent domain) of all origins that register passkeys
auth.rp.id=example.com
auth.rp.name=MyApp
# rp.origin must list every full origin (scheme+host+port) allowed to use passkeys
auth.rp.origin=http://localhost:7181,http://localhost:8080,https://www.example.com
```

---

## Connecting a Quarkus Client

### 1. Add two properties to the client's application.properties

```properties
# URL that both the SERVER and BROWSER can reach oauth-it on.
# Use the public HTTPS URL (not localhost) so the frontend JS can also use it.
auth.oauth-it.url=https://www.example.com/auth

# Must match auth.introspect-secret in oauth-it
auth.introspect-secret=change-me-introspect-secret
```

> **Why the public URL and not `http://localhost:7181/auth`?**
> `auth.oauth-it.url` is passed to the HTML template where it becomes the `AuthClient`
> base URL used by the browser. If you use the internal localhost URL, browser requests
> target the server's own loopback — unreachable from outside. The public HTTPS URL
> goes through NGINX and works for both server-side introspect calls and client-side
> WebAuthn/token fetch calls.

### 2. Wire up AuthFilter (server-side token verification)

AuthFilter reads both properties to validate incoming tokens:

```java
@ConfigProperty(name = "auth.oauth-it.url")
String oauthItUrl;

@ConfigProperty(name = "auth.introspect-secret")
String introspectSecret;

// On each request, POST to oauthItUrl + "/introspect"
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create(oauthItUrl + "/introspect"))
    .header("Content-Type", "application/x-www-form-urlencoded")
    .header("X-Introspect-Secret", introspectSecret)
    .POST(HttpRequest.BodyPublishers.ofString("token=" + token))
    .build();
```

### 3. Wire up the frontend (AuthClient JS)

Pass `auth.oauth-it.url` from your Qute resource to the template:

```java
@ConfigProperty(name = "auth.oauth-it.url")
String oauthItUrl;

return index.data("oauthItUrl", oauthItUrl);
```

```html
<!-- In your Qute template: -->
<script src="{oauthItUrl}/auth-client.js"></script>
<script>
    const auth = new AuthClient('{oauthItUrl}', {
        clientId:    'myclient',
        redirectUri: location.origin + '/',

        onLogin: function(token) {
            // Store as cookie so AuthFilter can read it on the next server request
            document.cookie = 'access_token=' + token + '; path=/; max-age=900';
            // update UI...
        }
    });
    auth.showLogin(document.getElementById('auth-container'));
</script>
```

The `onLogin` callback receives the JWT. Store it as the `access_token` cookie — the
name AuthFilter looks for on incoming requests.

### 4. Register the client in oauth-it

Add an entry to `auth.clients` in oauth-it's `application.properties` for each
`client_id` + `redirect_uri` pair. Include trailing-slash variants since browsers
are inconsistent:

```properties
auth.clients=...,myclient:https://www.example.com/,myclient:https://www.example.com
```

### 5. Don't use auth.dev-bypass-userid in production

The `auth.dev-bypass-userid` property bypasses all authentication and injects a
hardcoded user. Any non-blank value activates it — do not set it to `none` or any
placeholder. Remove the property entirely from production configs.

---

## Deployment Checklist

- [ ] `auth.rp.id` set to your domain (not `localhost`)
- [ ] All allowed origins listed in `auth.rp.origin`
- [ ] `.well-known/webauthn` NGINX location added if RP ID is a parent domain
- [ ] `/auth/` proxy block added to every subdomain's NGINX server block
- [ ] All client `redirect_uri` values in `auth.clients` (with and without trailing slash)
- [ ] `auth.oauth-it.url` set to the **public HTTPS URL** in each client's config
- [ ] `auth.introspect-secret` matches in oauth-it and every client
- [ ] `auth.dev-bypass-userid` absent from all production configs
- [ ] `auth.jwt.secret` changed to a strong random value (min 32 chars)
