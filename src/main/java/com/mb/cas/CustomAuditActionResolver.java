package com.mb.cas;


import org.apereo.inspektr.audit.annotation.Audit;
import org.apereo.inspektr.audit.spi.AuditActionResolver;

public class CustomAuditActionResolver implements AuditActionResolver {


    @Override
    public String resolveFrom(org.aspectj.lang.JoinPoint auditableTarget, Object returnValue, Audit audit) {
        return null;
    }

    @Override
    public String resolveFrom(org.aspectj.lang.JoinPoint auditableTarget, Exception exception, Audit audit) {
        return null;
    }
}
