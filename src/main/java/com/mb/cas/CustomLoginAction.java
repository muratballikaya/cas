package com.mb.cas;

import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.services.ServicesManager;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.action.AbstractAction;

public class CustomLoginAction extends AbstractAction {

    private final AuthenticationSystemSupport authenticationSystemSupport;
    private final ServicesManager servicesManager;

    public CustomLoginAction(AuthenticationSystemSupport authenticationSystemSupport, ServicesManager servicesManager) {
        this.authenticationSystemSupport = authenticationSystemSupport;
        this.servicesManager = servicesManager;
    }

    @Override
    protected Event doExecute(RequestContext context) {
        try {

            return success();
        } catch (Exception e) {
            return error();
        }
    }
}

