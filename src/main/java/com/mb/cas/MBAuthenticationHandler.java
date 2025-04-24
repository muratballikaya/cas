package com.mb.cas;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

public class MBAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {


    public MBAuthenticationHandler(String name, ServicesManager servicesManager,
                                   PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }
    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws Throwable {
        return createHandlerResult(credential,
                principalFactory.createPrincipal(credential.getUsername()), null);
    }

    @Override
    public boolean preAuthenticate(Credential credential) {
        return super.preAuthenticate(credential);
    }

    @Override
    public AuthenticationHandlerExecutionResult postAuthenticate(Credential credential, AuthenticationHandlerExecutionResult result) {
        return super.postAuthenticate(credential, result);
    }
}
