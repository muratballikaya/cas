package com.mb.cas;

import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.mfa.trigger.PrincipalAttributeMultifactorAuthenticationTrigger;
import org.apereo.cas.authentication.mfa.trigger.RegisteredServiceMultifactorAuthenticationTrigger;
import org.apereo.cas.authentication.principal.attribute.PersonAttributeDao;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.multitenancy.TenantExtractor;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.configurer.DefaultLoginWebflowConfigurer;
import org.apereo.inspektr.audit.spi.AuditActionResolver;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.annotation.Order;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.mvc.servlet.FlowHandlerMapping;

import java.util.Collection;
import java.util.List;


@AutoConfiguration
@EnableConfigurationProperties(CasConfigurationProperties.class)
@ConfigurationPropertiesScan(basePackageClasses = CasConfigurationProperties.class)
public class CasOverlayOverrideConfiguration {

    private final ConfigurableApplicationContext applicationContext;

    public CasOverlayOverrideConfiguration(ConfigurableApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Bean
    @Qualifier("authenticationContextValidator")
    public MultifactorAuthenticationContextValidator authenticationContextValidator() {
        String failureMode = "OPEN"; // Example value, adjust as needed
        String principalAttributeNameTrigger = "mfa-required"; // Example value, adjust as needed
        return new DefaultMultifactorAuthenticationContextValidator(failureMode, principalAttributeNameTrigger, applicationContext);
    }


    @Bean
    @Qualifier("multifactorAuthenticationProviderSelector")
    public MultifactorAuthenticationProviderSelector multifactorAuthenticationProviderSelector() {
        return new CustomMultifactorAuthenticationProviderSelector();
    }

    @Bean
    @Qualifier("defaultMultifactorTriggerSelectionStrategy")
    public MultifactorAuthenticationTriggerSelectionStrategy multifactorAuthenticationTriggerSelectionStrategy(
            @Qualifier("mfaTriggers") Collection<MultifactorAuthenticationTrigger> triggers) {
        return new DefaultMultifactorAuthenticationTriggerSelectionStrategy(triggers);
    }

    @Bean
    @Qualifier("mfaTriggers")
    public Collection<MultifactorAuthenticationTrigger> mfaTriggers(
            @Qualifier("casProperties") CasConfigurationProperties casProperties,
            @Qualifier("authenticationContextValidator") MultifactorAuthenticationContextValidator authenticationContextValidator,
            @Qualifier("multifactorAuthenticationProviderResolver") MultifactorAuthenticationProviderResolver providerResolver,
            @Qualifier("applicationContext") ConfigurableApplicationContext applicationContext,
            @Qualifier("tenantExtractor") TenantExtractor tenantExtractor) {
        return List.of(
                new PrincipalAttributeMultifactorAuthenticationTrigger(casProperties, providerResolver, applicationContext, tenantExtractor),
                new RegisteredServiceMultifactorAuthenticationTrigger(casProperties, multifactorAuthenticationProviderSelector(), applicationContext, tenantExtractor)
        );
    }


    @Bean
    @Primary
    @Qualifier("casProperties")
    public CasConfigurationProperties casConfigurationProperties() {
        return new CasConfigurationProperties();
    }

    @Bean
    @Qualifier("multifactorAuthenticationProviderResolver")
    public MultifactorAuthenticationProviderResolver multifactorAuthenticationProviderResolver(
            @Qualifier("multifactorAuthenticationPrincipalResolver") MultifactorAuthenticationPrincipalResolver multifactorAuthenticationPrincipalResolver) {
        return new DefaultMultifactorAuthenticationProviderResolver(multifactorAuthenticationPrincipalResolver);
    }

    @Bean
    @Qualifier("multifactorAuthenticationPrincipalResolver")
    public MultifactorAuthenticationPrincipalResolver surrogateMultifactorAuthenticationPrincipalResolver() {
        return new CustomMultifactorAuthenticationPrincipalResolver();
    }

    @Bean
    @Qualifier("ticketCreationActionResolver")
    public AuditActionResolver auditActionResolver() {
        return new CustomAuditActionResolver();
    }

    @Bean
    @Qualifier("returnValueResourceResolver")
    public AuditResourceResolver customAuditResourceResolver() {
        return new CustomAuditResourceResolver();
    }

    @Bean
    @Qualifier("mbLoginAction")
    public CustomLoginAction mbLoginAction() {
        return new CustomLoginAction(
                applicationContext.getBean(AuthenticationSystemSupport.class),
                applicationContext.getBean(ServicesManager.class));
    }


    @ConditionalOnMissingBean(
            name = {"mbWebflowConfigurer"}
    )
    @Bean
    @Order(Integer.MIN_VALUE)
    @RefreshScope(
            proxyMode = ScopedProxyMode.DEFAULT
    )
    public CasWebflowConfigurer mbWebflowConfigurer(final ConfigurableApplicationContext applicationContext, final CasConfigurationProperties casProperties, @Qualifier("flowDefinitionRegistry") final FlowDefinitionRegistry flowDefinitionRegistry, @Qualifier("flowBuilderServices") final FlowBuilderServices flowBuilderServices) {
        MBWebflowConfigurer cfg = new MBWebflowConfigurer(flowBuilderServices, flowDefinitionRegistry, applicationContext, casProperties);
        cfg.setOrder(Integer.MIN_VALUE);
        return cfg;
    }

    @Bean
    @Qualifier("authenticationActionResolver")
    public AuditActionResolver authenticationActionResolver() {
        return new CustomAuditActionResolver();
    }

    @Bean
    @Qualifier("attributeRepository")
    public PersonAttributeDao personAttributeDao() {
        return new CustomPersonAttributeDao();
    }


}







