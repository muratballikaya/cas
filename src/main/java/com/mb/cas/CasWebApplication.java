package com.mb.cas;


import java.util.ArrayList;
import java.util.List;
import lombok.Generated;
import org.apache.commons.lang3.ArrayUtils;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.util.app.ApplicationUtils;
import org.apereo.cas.util.spring.boot.CasBanner;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.mail.MailSenderAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@EnableDiscoveryClient
@SpringBootApplication(
        proxyBeanMethods = false,
        exclude = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class, MailSenderAutoConfiguration.class, MongoAutoConfiguration.class, MongoDataAutoConfiguration.class}
)
@EnableConfigurationProperties({CasConfigurationProperties.class})
@EnableAspectJAutoProxy(
        proxyTargetClass = false
)
@EnableTransactionManagement(
        proxyTargetClass = false
)
@EnableScheduling
@EnableAsync(
        proxyTargetClass = false
)
@ComponentScan(basePackages ={ "org.apereo.cas", "com.mb.cas", "org.apereo.cas.config"})
@EnableAutoConfiguration
public class CasWebApplication {
    public static void main(final String[] args) {
        List<Class> applicationClasses = getApplicationSources(args);
        (new SpringApplicationBuilder(new Class[0])).sources((Class[])applicationClasses.toArray(ArrayUtils.EMPTY_CLASS_ARRAY)).banner(CasBanner.getInstance()).web(WebApplicationType.SERVLET).logStartupInfo(true).applicationStartup(ApplicationUtils.getApplicationStartup()).run(args);
    }

    protected static List<Class> getApplicationSources(final String[] args) {
        ArrayList<Class> applicationClasses = new ArrayList();
        applicationClasses.add(org.apereo.cas.web.CasWebApplication.class);
        ApplicationUtils.getApplicationEntrypointInitializers().forEach((init) -> {
            init.initialize(args);
            applicationClasses.addAll(init.getApplicationSources(args));
        });
        return applicationClasses;
    }

    @Generated
    public CasWebApplication() {
    }
}

