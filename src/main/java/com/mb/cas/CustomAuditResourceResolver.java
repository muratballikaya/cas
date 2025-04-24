package com.mb.cas;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.aspectj.lang.JoinPoint;

public class CustomAuditResourceResolver implements AuditResourceResolver {
    @Override
    public String[] resolveFrom(JoinPoint target, Object returnValue) {
        // Implement custom logic to resolve resources
        return new String[]{"CustomResource"};
    }

    @Override
    public String[] resolveFrom(JoinPoint target, Exception exception) {
        // Implement custom logic to resolve resources in case of exceptions
        return new String[]{"CustomResource"};
    }
}