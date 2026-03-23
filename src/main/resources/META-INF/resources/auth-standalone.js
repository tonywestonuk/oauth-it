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
                var clientId    = card.getAttribute('data-client-id')           || '';
                var redirectUri = card.getAttribute('data-redirect-uri')        || '';
                var challenge   = card.getAttribute('data-code-challenge')      || '';
                var method      = card.getAttribute('data-code-challenge-method') || 'S256';
                var url = authUrl + '/authorize';
                if (clientId && redirectUri && challenge) {
                    url += '?client_id=' + encodeURIComponent(clientId)
                        + '&redirect_uri=' + encodeURIComponent(redirectUri)
                        + '&response_type=code'
                        + '&code_challenge=' + encodeURIComponent(challenge)
                        + '&code_challenge_method=' + encodeURIComponent(method);
                }
                setTimeout(function () {
                    window.location.href = url;
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
    var signinBtn = document.getElementById('passkey-signin-btn');
    if (signinBtn) {
        var clientId    = card.getAttribute('data-client-id')           || '';
        var redirectUri = card.getAttribute('data-redirect-uri')        || '';
        var challenge   = card.getAttribute('data-code-challenge')      || '';
        var state       = card.getAttribute('data-state')               || '';

        // Use AuthClient only for its WebAuthn helper methods, not its token exchange.
        var loginHelper = new AuthClient(authUrl, {});

        signinBtn.addEventListener('click', async function () {
            loginHelper._clearError(document.body);
            var usernameInput = document.getElementById('username');
            var username = usernameInput ? usernameInput.value.trim() : '';
            if (!username) {
                loginHelper._showError(document.body, 'Please enter your username.');
                return;
            }

            signinBtn.disabled = true;
            signinBtn.textContent = 'Waiting for passkey\u2026';

            try {
                var startRes = await fetch(authUrl + '/webauthn/auth/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username })
                });
                var startData = await startRes.json();
                if (startData.error) throw new Error(startData.error);

                var requestOptions = loginHelper._parseAssertionOptions(startData.requestOptions);
                var assertion = await navigator.credentials.get({ publicKey: requestOptions });

                var finishRes = await fetch(authUrl + '/webauthn/auth/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        requestId:            startData.requestId,
                        assertion:            loginHelper._assertionToJson(assertion),
                        codeChallenge:        challenge,
                        codeChallengeMethod:  'S256',
                        clientId:             clientId,
                        redirectUri:          redirectUri,
                        state:                state
                    })
                });
                var finishData = await finishRes.json();
                if (finishData.error) throw new Error(finishData.error);

                // Redirect back to the client with the code so it can do the token exchange
                // using its own PKCE verifier (stored in the client's sessionStorage).
                var sep = redirectUri.indexOf('?') >= 0 ? '&' : '?';
                var dest = redirectUri + sep + 'code=' + encodeURIComponent(finishData.code);
                if (state) dest += '&state=' + encodeURIComponent(state);
                window.location.href = dest;

            } catch (err) {
                loginHelper._showError(document.body, err.message || 'Sign-in failed. Please try again.');
                signinBtn.disabled = false;
                signinBtn.textContent = 'Sign in with Passkey';
            }
        });
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
