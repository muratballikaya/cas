package com.mb.cas;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowExecutionPlan;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

@AutoConfiguration
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class MBWebflowConfiguration implements CasWebflowExecutionPlanConfigurer {

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("flowDefinitionRegistry")
    private FlowDefinitionRegistry loginFlowDefinitionRegistry;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private FlowBuilderServices flowBuilderServices;

    @ConditionalOnMissingBean(name = "casWebflowConfigurer")
    @Bean
    public CasWebflowConfigurer mbWebflowConfigurer() {
        return new MBWebflowConfigurer(flowBuilderServices,
                loginFlowDefinitionRegistry, (ConfigurableApplicationContext) applicationContext, casProperties);
    }

    @Override
    public void configureWebflowExecutionPlan(final CasWebflowExecutionPlan plan) {
        plan.registerWebflowConfigurer(mbWebflowConfigurer());
    }
}