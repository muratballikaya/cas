package com.mb.cas;

import lombok.Generated;
import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.authentication.adaptive.UnauthorizedAuthenticationException;
import org.apereo.cas.authentication.credential.RememberMeUsernamePasswordCredential;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.exceptions.InvalidLoginLocationException;
import org.apereo.cas.authentication.exceptions.InvalidLoginTimeException;
import org.apereo.cas.authentication.principal.Response;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.services.UnauthorizedServiceForPrincipalException;
import org.apereo.cas.services.UnauthorizedSsoServiceException;
import org.apereo.cas.ticket.UnsatisfiedAuthenticationPolicyException;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.web.flow.StringToCharArrayConverter;
import org.apereo.cas.web.flow.actions.ConsumerExecutionAction;
import org.apereo.cas.web.flow.configurer.AbstractCasWebflowConfigurer;
import org.apereo.cas.web.flow.resolver.DynamicTargetStateResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.webflow.action.SetAction;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.*;
import org.springframework.webflow.engine.builder.BinderConfiguration;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.engine.support.TransitionExecutingFlowExecutionExceptionHandler;
import org.springframework.webflow.execution.repository.NoSuchFlowExecutionException;

import javax.security.auth.login.*;
import java.util.Locale;
import java.util.Map;

public class MBWebflowConfigurer extends AbstractCasWebflowConfigurer {
    @Generated
    private static final Logger LOGGER = LoggerFactory.getLogger(org.apereo.cas.web.flow.configurer.DefaultLoginWebflowConfigurer.class);

    public MBWebflowConfigurer(final FlowBuilderServices flowBuilderServices, final FlowDefinitionRegistry flowDefinitionRegistry, final ConfigurableApplicationContext applicationContext, final CasConfigurationProperties casProperties) {
        super(flowBuilderServices, flowDefinitionRegistry, applicationContext, casProperties);
    }

    protected void doInitialize() {
        Flow flow = this.getLoginFlow();
        this.createInitialFlowActions(flow);
        this.createDefaultGlobalExceptionHandlers(flow);
        this.createDefaultEndStates(flow);
        this.createDefaultDecisionStates(flow);
        this.createDefaultActionStates(flow);
        this.createDefaultViewStates(flow);
        this.createRememberMeAuthnWebflowConfig(flow);
        this.setStartState(flow, "initialAuthenticationRequestValidationCheck");
    }

    protected void createInitialFlowActions(final Flow flow) {
        ActionList startActionList = flow.getStartActionList();
        startActionList.add(this.createEvaluateAction("initialFlowSetupAction"));
        startActionList.add(this.createEvaluateAction("verifyRequiredServiceAction"));
    }

    protected void createDefaultViewStates(final Flow flow) {
        this.createLoginFormView(flow);
        this.createAuthenticationWarningMessagesView(flow);
        this.createSessionStorageStates(flow);
    }

    protected void createLoginFormView(final Flow flow) {
        Map<String, Map<String, String>> propertiesToBind = Map.of("username", Map.of("required", "true"), "password", Map.of("converter", StringToCharArrayConverter.ID), "source", Map.of("required", "true"));
        BinderConfiguration binder = this.createStateBinderConfiguration(propertiesToBind);
        this.casProperties.getView().getCustomLoginFormFields().forEach((field, props) -> {
            String fieldName = String.format("customFields[%s]", field);
            binder.addBinding(new BinderConfiguration.Binding(fieldName, props.getConverter(), props.isRequired()));
        });
        ViewState state = this.createViewState(flow, "viewLoginForm", "login/casLoginView", binder);
        this.createStateModelBinding(state, "credential", UsernamePasswordCredential.class);
        Transition transition = this.createTransitionForState(state, "submit", "realSubmit");
        MutableAttributeMap<Object> attributes = transition.getAttributes();
        attributes.put("bind", Boolean.TRUE);
        attributes.put("validate", Boolean.TRUE);
        attributes.put("history", History.INVALIDATE);
    }

    protected void createAuthenticationWarningMessagesView(final Flow flow) {
        ViewState state = this.createViewState(flow, "showAuthenticationWarningMessages", "login/casLoginMessageView");
        SetAction setAction = this.createSetAction("requestScope.messages", "messageContext.allMessages");
        state.getEntryActionList().add(setAction);
        this.createTransitionForState(state, "proceed", "proceedFromAuthenticationWarningView");
        ActionState proceedAction = this.createActionState(flow, "proceedFromAuthenticationWarningView");
        proceedAction.getActionList().add(this.createEvaluateAction("sendTicketGrantingTicketAction"));
        this.createStateDefaultTransition(proceedAction, "serviceCheck");
    }

    protected void createRememberMeAuthnWebflowConfig(final Flow flow) {
        if (this.casProperties.getTicket().getTgt().getRememberMe().isEnabled()) {
            this.createFlowVariable(flow, "credential", RememberMeUsernamePasswordCredential.class);
            ViewState state = (ViewState)this.getState(flow, "viewLoginForm", ViewState.class);
            BinderConfiguration cfg = this.getViewStateBinderConfiguration(state);
            cfg.addBinding(new BinderConfiguration.Binding("rememberMe", (String)null, false));
        } else {
            this.createFlowVariable(flow, "credential", UsernamePasswordCredential.class);
        }

    }

    protected void createDefaultActionStates(final Flow flow) {
        this.createInitialLoginAction(flow);
        this.createRealSubmitAction(flow);
        this.createInitialAuthenticationRequestValidationCheckAction(flow);
        this.createCreateTicketGrantingTicketAction(flow);
        this.createSendTicketGrantingTicketAction(flow);
        this.createGenerateServiceTicketAction(flow);
        this.createGatewayServicesMgmtAction(flow);
        this.createServiceAuthorizationCheckAction(flow);
        this.createRedirectToServiceActionState(flow);
        this.createHandleAuthenticationFailureAction(flow);
        this.createTerminateSessionAction(flow);
        this.createTicketGrantingTicketCheckAction(flow);
    }

    protected void createRealSubmitAction(final Flow flow) {
        ActionState state = this.createActionState(flow, "realSubmit", new String[]{"authenticationViaFormAction"});
        this.createTransitionForState(state, "warn", "warn");
        this.createTransitionForState(state, "success", "createTicketGrantingTicket");
        this.createTransitionForState(state, "successWithWarnings", "showAuthenticationWarningMessages");
        this.createTransitionForState(state, "authenticationFailure", "handleAuthenticationFailure");
        this.createTransitionForState(state, "error", "initializeLoginForm");
        this.createTransitionForState(state, "valid", "serviceCheck");
        this.createTransitionForState(state, "generateServiceTicket", "generateServiceTicket");
    }

    protected void createTicketGrantingTicketCheckAction(final Flow flow) {
        ActionState action = this.createActionState(flow, "ticketGrantingTicketCheck", new String[]{"ticketGrantingTicketCheckAction"});
        this.createTransitionForState(action, "notExists", "gatewayRequestCheck");
        this.createTransitionForState(action, "invalid", "terminateSession");
        this.createTransitionForState(action, "valid", "hasServiceCheck");
    }

    protected void createInitialAuthenticationRequestValidationCheckAction(final Flow flow) {
        ActionState action = this.createActionState(flow, "initialAuthenticationRequestValidationCheck", new String[]{"initialAuthenticationRequestValidationAction"});
        action.getEntryActionList().add(this.createEvaluateAction("verifyRequiredServiceAction"));
        this.createTransitionForState(action, "authenticationFailure", "handleAuthenticationFailure");
        this.createTransitionForState(action, "error", "initializeLoginForm");
        this.createTransitionForState(action, "success", "ticketGrantingTicketCheck");
        this.createTransitionForState(action, "successWithWarnings", "showAuthenticationWarningMessages");
        this.createTransitionForState(action, "readFromBrowserStorage", "casBrowserStorageReadView");
    }

    protected void createTerminateSessionAction(final Flow flow) {
        ActionState terminateSession = this.createActionState(flow, "terminateSession", this.createEvaluateAction("terminateSessionAction"));
        this.createStateDefaultTransition(terminateSession, "gatewayRequestCheck");
    }

    protected void createSendTicketGrantingTicketAction(final Flow flow) {
        ActionState action = this.createActionState(flow, "sendTicketGrantingTicket", new String[]{"sendTicketGrantingTicketAction"});
        action.getExitActionList().add(this.createEvaluateAction("singleSignOnSessionCreated"));
        this.createTransitionForState(action, "writeToBrowserStorage", "casBrowserStorageWriteView");
        this.createTransitionForState(action, "success", "serviceCheck");
        this.createTransitionForState(action, "successWithWarnings", "showAuthenticationWarningMessages");
    }

    private void createSessionStorageStates(final Flow flow) {
        ViewState writeStorage = this.createViewState(flow, "casBrowserStorageWriteView", "storage/casBrowserStorageWriteView");
        writeStorage.getEntryActionList().add(this.createEvaluateAction("writeBrowserStorageAction"));
        this.createTransitionForState(writeStorage, "continue", "serviceCheck");
        ViewState readStorage = this.createViewState(flow, "casBrowserStorageReadView", "storage/casBrowserStorageReadView");
        readStorage.getRenderActionList().add(this.createEvaluateAction("putBrowserStorageAction"));
        this.createTransitionForState(readStorage, "continue", "verifyBrowserStorageRead");
        ActionState verifyStorage = this.createActionState(flow, "verifyBrowserStorageRead", new String[]{"readBrowserStorageAction"});
        this.createTransitionForState(verifyStorage, "success", new DynamicTargetStateResolver(flow));
        this.createTransitionForState(verifyStorage, "skip", "initializeLoginForm");
        this.createTransitionForState(verifyStorage, "readFromBrowserStorage", "casBrowserStorageReadView");
    }

    protected void createCreateTicketGrantingTicketAction(final Flow flow) {
        ActionState action = this.createActionState(flow, "createTicketGrantingTicket", new String[]{"createTicketGrantingTicketAction"});
        this.createTransitionForState(action, "successWithWarnings", "showAuthenticationWarningMessages");
        this.createTransitionForState(action, "success", "sendTicketGrantingTicket");
    }

    protected void createGenerateServiceTicketAction(final Flow flow) {
        ActionState handler = this.createActionState(flow, "generateServiceTicket", this.createEvaluateAction("generateServiceTicketAction"));
        this.createTransitionForState(handler, "success", "redirect");
        this.createTransitionForState(handler, "warn", "warn");
        this.createTransitionForState(handler, "authenticationFailure", "handleAuthenticationFailure");
        this.createTransitionForState(handler, "error", "initializeLoginForm");
        this.createTransitionForState(handler, "gateway", "gatewayServicesManagementCheck");
    }

    protected void createHandleAuthenticationFailureAction(final Flow flow) {
        ActionState authnFailure = this.createActionState(flow, "handleAuthenticationFailure", new String[]{"authenticationExceptionHandler"});
        this.createTransitionForState(authnFailure, AccountDisabledException.class.getSimpleName(), "casAccountDisabledView");
        this.createTransitionForState(authnFailure, AccountLockedException.class.getSimpleName(), "casAccountLockedView");
        this.createTransitionForState(authnFailure, AccountExpiredException.class.getSimpleName(), "casExpiredPassView");
        this.createTransitionForState(authnFailure, AccountLockedException.class.getSimpleName(), "casAccountLockedView");
        this.createTransitionForState(authnFailure, AccountPasswordMustChangeException.class.getSimpleName(), "casMustChangePassView");
        this.createTransitionForState(authnFailure, CredentialExpiredException.class.getSimpleName(), "casExpiredPassView");
        this.createTransitionForState(authnFailure, InvalidLoginLocationException.class.getSimpleName(), "casBadWorkstationView");
        this.createTransitionForState(authnFailure, InvalidLoginTimeException.class.getSimpleName(), "casBadHoursView");
        this.createTransitionForState(authnFailure, FailedLoginException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(authnFailure, AccountNotFoundException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(authnFailure, UnauthorizedServiceForPrincipalException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(authnFailure, PrincipalException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(authnFailure, UnsatisfiedAuthenticationPolicyException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(authnFailure, UnauthorizedAuthenticationException.class.getSimpleName(), "casAuthenticationBlockedView");
        this.createTransitionForState(authnFailure, "serviceUnauthorizedCheck", "serviceUnauthorizedCheck");
        this.createTransitionForState(authnFailure, "redirect", "redirectView");
        this.createStateDefaultTransition(authnFailure, "initializeLoginForm");
        authnFailure.getEntryActionList().add(this.createEvaluateAction("clearWebflowCredentialsAction"));
    }

    protected void createRedirectToServiceActionState(final Flow flow) {
        ActionState redirectToView = this.createActionState(flow, "redirect", new String[]{"redirectToServiceAction"});
        this.createTransitionForState(redirectToView, Response.ResponseType.POST.name().toLowerCase(Locale.ENGLISH), "postView");
        this.createTransitionForState(redirectToView, Response.ResponseType.HEADER.name().toLowerCase(Locale.ENGLISH), "headerView");
        this.createTransitionForState(redirectToView, Response.ResponseType.REDIRECT.name().toLowerCase(Locale.ENGLISH), "redirectView");
        redirectToView.getExitActionList().add(this.createEvaluateAction("clearWebflowCredentialsAction"));
    }

    protected void createServiceAuthorizationCheckAction(final Flow flow) {
        ActionState serviceAuthorizationCheck = this.createActionState(flow, "serviceAuthorizationCheck", new String[]{"serviceAuthorizationCheck"});
        this.createStateDefaultTransition(serviceAuthorizationCheck, "initializeLoginForm");
    }

    protected void createGatewayServicesMgmtAction(final Flow flow) {
        ActionState gatewayServicesManagementCheck = this.createActionState(flow, "gatewayServicesManagementCheck", new String[]{"gatewayServicesManagementCheck"});
        this.createTransitionForState(gatewayServicesManagementCheck, "success", "redirect");
    }

    protected void createDefaultEndStates(final Flow flow) {
        this.createRedirectUnauthorizedServiceUrlEndState(flow);
        this.createServiceErrorEndState(flow);
        this.createWebflowConfigurationErrorEndState(flow);
        this.createServiceErrorEndState(flow);
        this.createRedirectEndState(flow);
        this.createPostEndState(flow);
        this.createInjectHeadersActionState(flow);
        this.createGenericLoginSuccessEndState(flow);
        this.createServiceWarningViewState(flow);
        this.createEndWebflowEndState(flow);
    }

    protected void createEndWebflowEndState(final Flow flow) {
        this.createEndState(flow, "endWebflowExecution");
    }

    protected void createRedirectEndState(final Flow flow) {
        this.createEndState(flow, "redirectView", "requestScope.url", true);
    }

    protected void createPostEndState(final Flow flow) {
        this.createEndState(flow, "postView", "casPostResponseView");
    }

    protected void createInjectHeadersActionState(final Flow flow) {
        ActionState headerState = this.createActionState(flow, "headerView", new String[]{"injectResponseHeadersAction"});
        this.createTransitionForState(headerState, "success", "endWebflowExecution");
        this.createTransitionForState(headerState, "redirect", "redirectView");
    }

    protected void createRedirectUnauthorizedServiceUrlEndState(final Flow flow) {
        EndState state = this.createEndState(flow, "viewRedirectToUnauthorizedUrlView", "error/casUnauthorizedServiceRedirectView");
        state.getEntryActionList().add(this.createEvaluateAction("redirectUnauthorizedServiceUrlAction"));
    }

    protected void createServiceErrorEndState(final Flow flow) {
        this.createEndState(flow, "viewServiceErrorView", "error/casServiceErrorView");
    }

    protected void createWebflowConfigurationErrorEndState(final Flow flow) {
        EndState state = this.createEndState(flow, "viewWebflowConfigurationErrorView", "error/casWebflowConfigErrorView");
        state.getEntryActionList().add(new ConsumerExecutionAction((context) -> {
            if (context.getFlashScope().contains("rootCauseException")) {
                Exception rootException = (Exception)context.getFlashScope().get("rootCauseException");
                LoggingUtils.error(LOGGER, rootException);
            }

        }));
    }

    protected void createGenericLoginSuccessEndState(final Flow flow) {
        EndState state = this.createEndState(flow, "viewGenericLoginSuccess", "login/casGenericSuccessView");
        state.getEntryActionList().add(this.createEvaluateAction("genericSuccessViewAction"));
    }

    protected void createServiceWarningViewState(final Flow flow) {
        ViewState stateWarning = this.createViewState(flow, "showWarningView", "login/casConfirmView");
        this.createTransitionForState(stateWarning, "success", "finalizeWarning");
        ActionState finalizeWarn = this.createActionState(flow, "finalizeWarning", new String[]{"serviceWarningAction"});
        this.createTransitionForState(finalizeWarn, "redirect", "redirect");
    }

    protected void createDefaultGlobalExceptionHandlers(final Flow flow) {
        TransitionExecutingFlowExecutionExceptionHandler handler = new TransitionExecutingFlowExecutionExceptionHandler();
        handler.add(UnauthorizedSsoServiceException.class, "viewLoginForm");
        handler.add(NoSuchFlowExecutionException.class, "viewServiceErrorView");
        handler.add(UnauthorizedServiceException.class, "serviceUnauthorizedCheck");
        handler.add(UnauthorizedServiceForPrincipalException.class, "serviceUnauthorizedCheck");
        handler.add(PrincipalException.class, "serviceUnauthorizedCheck");
        handler.add(NoMatchingTransitionException.class, "viewWebflowConfigurationErrorView");
        flow.getExceptionHandlerSet().add(handler);
    }

    protected void createDefaultDecisionStates(final Flow flow) {
        this.createServiceUnauthorizedCheckDecisionState(flow);
        this.createServiceCheckDecisionState(flow);
        this.createWarnDecisionState(flow);
        this.createGatewayRequestCheckDecisionState(flow);
        this.createHasServiceCheckDecisionState(flow);
        this.createRenewCheckActionState(flow);
    }

    protected void createServiceUnauthorizedCheckDecisionState(final Flow flow) {
        DecisionState decision = this.createDecisionState(flow, "serviceUnauthorizedCheck", "flowScope.unauthorizedRedirectUrl != null", "viewRedirectToUnauthorizedUrlView", "viewServiceErrorView");
        decision.getEntryActionList().add(this.createEvaluateAction("setServiceUnauthorizedRedirectUrlAction"));
    }

    protected void createServiceCheckDecisionState(final Flow flow) {
        this.createDecisionState(flow, "serviceCheck", "flowScope.service != null", "generateServiceTicket", "viewGenericLoginSuccess");
    }

    protected void createWarnDecisionState(final Flow flow) {
        this.createDecisionState(flow, "warn", "flowScope.warnCookieValue", "showWarningView", "redirect");
    }

    protected void createGatewayRequestCheckDecisionState(final Flow flow) {
        this.createDecisionState(flow, "gatewayRequestCheck", "requestParameters.gateway != '' and requestParameters.gateway != null and flowScope.service != null", "gatewayServicesManagementCheck", "serviceAuthorizationCheck");
    }

    protected void createHasServiceCheckDecisionState(final Flow flow) {
        this.createDecisionState(flow, "hasServiceCheck", "flowScope.service != null", "renewRequestCheck", "viewGenericLoginSuccess");
    }

    protected void createRenewCheckActionState(final Flow flow) {
        ActionState action = this.createActionState(flow, "renewRequestCheck", new String[]{"renewAuthenticationRequestCheckAction"});
        this.createTransitionForState(action, "proceed", "generateServiceTicket");
        this.createTransitionForState(action, "renew", "serviceAuthorizationCheck");
        this.createStateDefaultTransition(action, "serviceAuthorizationCheck");
    }

    private void createInitialLoginAction(final Flow flow) {
        ActionState state = this.createActionState(flow, "initializeLoginForm", new String[]{"initializeLoginAction"});
        this.createTransitionForState(state, "success", "afterInitializeLoginForm");
        ActionState afterState = this.createActionState(flow, "afterInitializeLoginForm", this.createSetAction("requestScope.initialized", "true"));
        this.createTransitionForState(afterState, "success", "viewLoginForm");
    }
}
