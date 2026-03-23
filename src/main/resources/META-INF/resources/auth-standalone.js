/**
 * auth-standalone.js
 * Auto-wires passkey buttons on the standalone (non-embedded) signup and login pages.
 * Reads auth server URL from data-auth-url attribute on .auth-card.
 */
(function () {
    var card = document.querySelector('.auth-card');
    if (!card) return;

    var authUrl = card.getAttribute('data-auth-url');
    if (!authUrl) return;

    // ---- Signup page ----
    if (document.getElementById('passkey-register-btn')) {
        var signupAuth = new AuthClient(authUrl, {
            onSignup: function () {
                setTimeout(function () {
                    window.location.href = authUrl + '/authorize';
                }, 2000);
            }
        });
        signupAuth._wireSignup(document.body);
    }

    // ---- Recovery page ----
    var recoveryBtn = document.getElementById('passkey-recovery-btn');
    if (recoveryBtn) {
        var recoveryToken = card.getAttribute('data-recovery-token') || '';
        recoveryBtn.addEventListener('click', function () {
            recoveryBtn.disabled = true;
            recoveryBtn.textContent = 'Setting up passkey\u2026';
            var container = document.getElementById('recovery-container') || document.body;

            fetch(authUrl + '/webauthn/recover/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recoveryToken: recoveryToken })
            })
            .then(function (r) { return r.json(); })
            .then(function (startData) {
                if (startData.error) throw new Error(startData.error);
                var parsed = JSON.parse(startData.creationOptions);
                var opts = parsed.publicKey || parsed;
                opts.challenge = _b64ToBuffer(opts.challenge);
                opts.user.id   = _b64ToBuffer(opts.user.id);
                if (opts.excludeCredentials) {
                    opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
                        return Object.assign({}, c, { id: _b64ToBuffer(c.id) });
                    });
                }
                return navigator.credentials.create({ publicKey: opts })
                .then(function (credential) {
                    return fetch(authUrl + '/webauthn/register/finish', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            requestId: startData.requestId,
                            credential: JSON.stringify({
                                id: credential.id,
                                rawId: _bufToB64(credential.rawId),
                                type: credential.type,
                                response: {
                                    clientDataJSON:    _bufToB64(credential.response.clientDataJSON),
                                    attestationObject: _bufToB64(credential.response.attestationObject)
                                },
                                clientExtensionResults: credential.getClientExtensionResults()
                            })
                        })
                    });
                });
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.error) throw new Error(data.error);
                container.innerHTML = '<div class="auth-card"><h1>Passkey Registered!</h1>'
                    + '<p>Your new passkey is ready.</p>'
                    + '<div class="auth-links"><a href="' + authUrl + '/authorize">Sign in now</a></div></div>';
            })
            .catch(function (err) {
                var errEl = container.querySelector('.auth-error') || document.createElement('div');
                errEl.className = 'auth-error';
                errEl.textContent = err.message || 'Recovery failed. Please try again.';
                var c = container.querySelector('.auth-card');
                if (c && !c.contains(errEl)) c.prepend(errEl);
                recoveryBtn.disabled = false;
                recoveryBtn.textContent = 'Register New Passkey';
            });
        });
    }

    // ---- Login page ----
    if (document.getElementById('passkey-signin-btn')) {
        var clientId    = card.getAttribute('data-client-id')    || '';
        var redirectUri = card.getAttribute('data-redirect-uri') || authUrl;
        var challenge   = card.getAttribute('data-code-challenge') || '';
        var state       = card.getAttribute('data-state')          || '';

        var loginAuth = new AuthClient(authUrl, {
            clientId:    clientId,
            redirectUri: redirectUri,
            onLogin: function () {
                window.location.href = redirectUri || authUrl;
            }
        });
        loginAuth._wireLogin(document.body, challenge, state);
    }
    function _b64ToBuffer(base64url) {
        var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        var binary = atob(base64);
        var bytes  = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function _bufToB64(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
})();
