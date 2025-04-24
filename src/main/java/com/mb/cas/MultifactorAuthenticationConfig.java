package com.mb.cas;


import org.apereo.cas.authentication.DefaultMultifactorAuthenticationContextValidator;
import org.apereo.cas.authentication.MultifactorAuthenticationContextValidator;
import org.apereo.cas.config.CasJpaServiceRegistryAutoConfiguration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apereo.cas.authentication.principal.attribute.PersonAttributeDao;
@Configuration
@AutoConfiguration
public class MultifactorAuthenticationConfig {
}