package com.oauth_it.service;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

@ApplicationScoped
public class WebAuthnService {

    @ConfigProperty(name = "auth.rp.id")
    String rpId;

    @ConfigProperty(name = "auth.rp.name")
    String rpName;

    @ConfigProperty(name = "auth.rp.origin")
    String rpOrigin;

    @Inject
    CredentialStore credentialStore;

    private RelyingParty rp;

    @PostConstruct
    void init() {
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id(rpId)
                .name(rpName)
                .build();

        rp = RelyingParty.builder()
                .identity(identity)
                .credentialRepository(credentialStore)
                .origins(Collections.singleton(rpOrigin))
                .build();
    }

    // ------------------------------------------------------------------ //
    // Registration
    // ------------------------------------------------------------------ //

    public PublicKeyCredentialCreationOptions startRegistration(String username, String userId) {
        ByteArray userHandle = new ByteArray(userId.getBytes(StandardCharsets.UTF_8));

        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(username)
                .id(userHandle)
                .build();

        return rp.startRegistration(StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .residentKey(ResidentKeyRequirement.PREFERRED)
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .build())
                .build());
    }

    public RegistrationResult finishRegistration(
            PublicKeyCredentialCreationOptions request,
            String credentialJson) throws RegistrationFailedException, IOException {

        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                PublicKeyCredential.parseRegistrationResponseJson(credentialJson);

        return rp.finishRegistration(FinishRegistrationOptions.builder()
                .request(request)
                .response(pkc)
                .build());
    }

    // ------------------------------------------------------------------ //
    // Authentication
    // ------------------------------------------------------------------ //

    public AssertionRequest startAssertion(String username) {
        return rp.startAssertion(StartAssertionOptions.builder()
                .username(username)
                .build());
    }

    public AssertionResult finishAssertion(
            AssertionRequest request,
            String assertionJson) throws AssertionFailedException, IOException {

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                PublicKeyCredential.parseAssertionResponseJson(assertionJson);

        return rp.finishAssertion(FinishAssertionOptions.builder()
                .request(request)
                .response(pkc)
                .build());
    }
}
