package com.mb.cas;


import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class MBAuthenticationConfigurer {

    @Autowired
    ServicesManager servicesManager;

    @Autowired
    @Qualifier("principalFactory")
    PrincipalFactory  principleFactory;

    @Bean
    public AuthenticationHandler mbAuthenticationHandler(
            final CasConfigurationProperties casProperties) {

        var handler = new MBAuthenticationHandler(
                "mbAuthenticationHandler",
                servicesManager, // ServicesManager is typically injected here
                principleFactory, // PrincipalFactory is typically injected here
                1 );
        /*
            Configure the handler by invoking various setter methods, etc.
            Note that you also have full access to the collection of resolved CAS settings.
            Note that each authentication handler may optionally qualify for an 'order`
            as well as a unique name.
        */
        return handler;
    }

    @Bean
    public AuthenticationEventExecutionPlanConfigurer myPlan(
            @Qualifier("mbAuthenticationHandler")
            final AuthenticationHandler myAuthenticationHandler) {
        return plan -> {
            plan.registerAuthenticationHandler(myAuthenticationHandler);
        };
    }
}
