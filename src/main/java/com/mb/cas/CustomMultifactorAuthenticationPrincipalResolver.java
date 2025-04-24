package com.mb.cas;

import org.apereo.cas.authentication.MultifactorAuthenticationPrincipalResolver;
import org.apereo.cas.authentication.principal.Principal;

public class CustomMultifactorAuthenticationPrincipalResolver implements MultifactorAuthenticationPrincipalResolver {


    @Override
    public int getOrder() {
        return MultifactorAuthenticationPrincipalResolver.super.getOrder();
    }

    @Override
    public boolean supports(Principal principal) {
        return MultifactorAuthenticationPrincipalResolver.super.supports(principal);
    }

    @Override
    public Principal resolve(Principal principal) {
        return principal;
    }
}