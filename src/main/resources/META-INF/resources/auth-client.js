/**
 * auth-client.js — WebAuthn / Passkey auth client
 * Served at /auth-client.js
 *
 * Usage:
 *   <script src="https://auth.example.com/auth-client.js"></script>
 *   <script>
 *     const auth = new AuthClient('https://auth.example.com', {
 *       clientId:    'my-app',
 *       redirectUri: 'https://myapp.example.com/',
 *       cookieName:  'access_token',   // optional, default 'access_token'
 *       onLogin:  () => location.reload(),
 *       onSignup: () => auth.showLogin(container),
 *     });
 *   </script>
 *
 * The client handles:
 *   - Setting and clearing the access_token cookie
 *   - Silently refreshing the token 30 minutes before expiry
 *   - Re-scheduling the refresh timer on every page load
 */
class AuthClient {
    constructor(authServerUrl, options = {}) {
        this.url        = authServerUrl.replace(/\/$/, '');
        this.clientId   = options.clientId   || '';
        this.redirectUri = options.redirectUri || '';
        this.onLogin    = options.onLogin    || (() => {});
        this.onSignup   = options.onSignup   || (() => {});
        this._cookieName  = options.cookieName || 'access_token';
        this._refreshTimer = null;
        this._initRefreshTimer();
    }

    // ------------------------------------------------------------------ //
    // Public API
    // ------------------------------------------------------------------ //

    async showLogin(container) {
        const { verifier, challenge } = await this._pkce();
        const state = this._rand(16);
        sessionStorage.setItem('_auth_verifier', verifier);
        sessionStorage.setItem('_auth_state', state);

        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            code_challenge: challenge,
            code_challenge_method: 'S256',
            state,
            embed: 'true',
        });

        await this._inject(container, `/authorize?${params}`);
        this._wireLogin(container, challenge, state);
    }

    async showSignup(container) {
        await this._inject(container, '/signup?embed=true');
        this._wireSignup(container);
    }

    logout() {
        if (this._refreshTimer) clearTimeout(this._refreshTimer);
        this._refreshTimer = null;
        localStorage.removeItem('_auth_access_token');
        localStorage.removeItem('_auth_token_expiry');
        document.cookie = `${this._cookieName}=; path=/; max-age=0; SameSite=Lax`;
    }

    // ------------------------------------------------------------------ //
    // Login (WebAuthn assertion)
    // ------------------------------------------------------------------ //

    _wireLogin(container, codeChallenge, state) {
        const btn = container.querySelector('#passkey-signin-btn');
        if (!btn) return;

        btn.addEventListener('click', async () => {
            this._clearError(container);
            const usernameInput = container.querySelector('#username');
            const username = usernameInput ? usernameInput.value.trim() : '';

            if (!username) {
                this._showError(container, 'Please enter your username.');
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Waiting for passkey\u2026';

            try {
                const startRes = await fetch(this.url + '/webauthn/auth/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username }),
                });
                const startData = await startRes.json();
                if (startData.error) throw new Error(startData.error);

                const requestOptions = this._parseAssertionOptions(startData.requestOptions);
                const assertion = await navigator.credentials.get({ publicKey: requestOptions });

                const finishRes = await fetch(this.url + '/webauthn/auth/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        requestId: startData.requestId,
                        assertion: this._assertionToJson(assertion),
                        codeChallenge,
                        codeChallengeMethod: 'S256',
                        clientId: this.clientId,
                        redirectUri: this.redirectUri,
                        state,
                    }),
                });
                const finishData = await finishRes.json();
                if (finishData.error) throw new Error(finishData.error);

                await this._exchangeCode(finishData.code);

            } catch (err) {
                this._showError(container, err.message || 'Sign-in failed. Please try again.');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Sign in with Passkey';
            }
        });
    }

    // ------------------------------------------------------------------ //
    // Signup (WebAuthn registration)
    // ------------------------------------------------------------------ //

    _wireSignup(container) {
        const btn = container.querySelector('#passkey-register-btn');
        if (!btn) return;

        btn.addEventListener('click', async () => {
            this._clearError(container);
            const username = (container.querySelector('#username')?.value || '').trim();

            if (!username) {
                this._showError(container, 'Please enter a username.');
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Setting up passkey\u2026';

            try {
                const startRes = await fetch(this.url + '/webauthn/register/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username }),
                });
                const startData = await startRes.json();
                if (startData.error) throw new Error(startData.error);

                const creationOptions = this._parseCreationOptions(startData.creationOptions);
                const credential = await navigator.credentials.create({ publicKey: creationOptions });

                const finishRes = await fetch(this.url + '/webauthn/register/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        requestId: startData.requestId,
                        credential: this._credentialToJson(credential),
                    }),
                });
                const finishData = await finishRes.json();
                if (finishData.error) throw new Error(finishData.error);

                container.innerHTML = `
                    <div class="auth-card auth-card--wide">
                        <h1>Passkey Created!</h1>
                        <p>Your account is ready. You can now sign in with your passkey.</p>
                    </div>`;
                this.onSignup();

            } catch (err) {
                this._showError(container, err.message || 'Registration failed. Please try again.');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Register with Passkey';
            }
        });
    }

    // ------------------------------------------------------------------ //
    // Token exchange + rolling refresh
    // ------------------------------------------------------------------ //

    async _exchangeCode(code) {
        const verifier = sessionStorage.getItem('_auth_verifier');
        const res = await fetch(this.url + '/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type:    'authorization_code',
                code,
                code_verifier: verifier,
                client_id:     this.clientId,
                redirect_uri:  this.redirectUri,
            }),
        });
        const data = await res.json();
        if (!data.access_token) throw new Error('Token exchange failed.');

        sessionStorage.removeItem('_auth_verifier');
        sessionStorage.removeItem('_auth_state');

        this._storeToken(data.access_token, data.expires_in || 172800);
        this.onLogin(data.access_token);
    }

    async _doRefresh() {
        const token = localStorage.getItem('_auth_access_token');
        if (!token) return;
        try {
            const res = await fetch(this.url + '/token/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ token }),
            });
            if (!res.ok) { this._clearStored(); return; }
            const data = await res.json();
            if (!data.access_token) { this._clearStored(); return; }
            this._storeToken(data.access_token, data.expires_in || 172800);
        } catch (e) {
            // Network error — leave cookie alone, retry next schedule
        }
    }

    _storeToken(token, expiresIn) {
        localStorage.setItem('_auth_access_token', token);
        localStorage.setItem('_auth_token_expiry', String(Date.now() + expiresIn * 1000));
        document.cookie = `${this._cookieName}=${token}; path=/; max-age=${expiresIn}; SameSite=Lax`;
        this._scheduleRefresh(expiresIn);
    }

    _scheduleRefresh(expiresIn) {
        if (this._refreshTimer) clearTimeout(this._refreshTimer);
        // Refresh 30 minutes before expiry (minimum 5 seconds)
        const delay = Math.max((expiresIn - 30 * 60) * 1000, 5000);
        this._refreshTimer = setTimeout(() => this._doRefresh(), delay);
    }

    _initRefreshTimer() {
        const expiry = parseInt(localStorage.getItem('_auth_token_expiry') || '0', 10);
        if (!expiry) return;
        const remainingSecs = (expiry - Date.now()) / 1000;
        if (remainingSecs <= 0) return;
        this._scheduleRefresh(remainingSecs);
    }

    _clearStored() {
        localStorage.removeItem('_auth_access_token');
        localStorage.removeItem('_auth_token_expiry');
        document.cookie = `${this._cookieName}=; path=/; max-age=0; SameSite=Lax`;
    }

    // ------------------------------------------------------------------ //
    // WebAuthn binary conversion helpers
    // ------------------------------------------------------------------ //

    _parseCreationOptions(json) {
        const parsed = JSON.parse(json);
        const opts = parsed.publicKey || parsed;
        opts.challenge = this._b64ToBuffer(opts.challenge);
        opts.user.id   = this._b64ToBuffer(opts.user.id);
        if (opts.excludeCredentials) {
            opts.excludeCredentials = opts.excludeCredentials.map(c => ({
                ...c, id: this._b64ToBuffer(c.id)
            }));
        }
        return opts;
    }

    _parseAssertionOptions(json) {
        const parsed = JSON.parse(json);
        const opts = parsed.publicKey || parsed;
        opts.challenge = this._b64ToBuffer(opts.challenge);
        if (opts.allowCredentials) {
            opts.allowCredentials = opts.allowCredentials.map(c => ({
                ...c, id: this._b64ToBuffer(c.id)
            }));
        }
        return opts;
    }

    _credentialToJson(credential) {
        return JSON.stringify({
            id:    credential.id,
            rawId: this._bufToB64(credential.rawId),
            type:  credential.type,
            response: {
                clientDataJSON:    this._bufToB64(credential.response.clientDataJSON),
                attestationObject: this._bufToB64(credential.response.attestationObject),
            },
            clientExtensionResults: credential.getClientExtensionResults(),
        });
    }

    _assertionToJson(assertion) {
        return JSON.stringify({
            id:    assertion.id,
            rawId: this._bufToB64(assertion.rawId),
            type:  assertion.type,
            response: {
                clientDataJSON:    this._bufToB64(assertion.response.clientDataJSON),
                authenticatorData: this._bufToB64(assertion.response.authenticatorData),
                signature:         this._bufToB64(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? this._bufToB64(assertion.response.userHandle) : null,
            },
            clientExtensionResults: assertion.getClientExtensionResults(),
        });
    }

    _b64ToBuffer(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(base64);
        const bytes  = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    _bufToB64(buffer) {
        const bytes  = new Uint8Array(buffer);
        let binary   = '';
        for (const b of bytes) binary += String.fromCharCode(b);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    // ------------------------------------------------------------------ //
    // UI helpers
    // ------------------------------------------------------------------ //

    async _inject(container, path) {
        container.innerHTML = '<p style="text-align:center;padding:2rem;color:#888">Loading\u2026</p>';
        try {
            const res = await fetch(this.url + path);
            container.innerHTML = await res.text();
        } catch {
            container.innerHTML = '<p style="text-align:center;padding:2rem;color:#c00">Could not reach auth server.</p>';
        }
    }

    _showError(container, msg) {
        let el = container.querySelector('.auth-error');
        if (!el) {
            el = document.createElement('div');
            el.className = 'auth-error';
            const card = container.querySelector('.auth-card');
            if (card) card.prepend(el); else container.prepend(el);
        }
        el.textContent = msg;
    }

    _clearError(container) {
        const el = container.querySelector('.auth-error');
        if (el) el.textContent = '';
    }

    async _pkce() {
        const verifier  = this._rand(64);
        const digest    = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        return { verifier, challenge };
    }

    _rand(len) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        return Array.from(crypto.getRandomValues(new Uint8Array(len)))
            .map(b => chars[b % chars.length]).join('');
    }
}
