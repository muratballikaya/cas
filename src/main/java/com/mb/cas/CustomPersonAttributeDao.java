package com.mb.cas;


import org.apereo.cas.authentication.attribute.BasePersonAttributeDao;
import org.apereo.cas.authentication.principal.attribute.PersonAttributeDaoFilter;
import org.apereo.cas.authentication.principal.attribute.PersonAttributes;
import org.apereo.inspektr.audit.annotation.Audit;
import org.apereo.inspektr.audit.spi.AuditActionResolver;

import java.util.Map;
import java.util.Set;

public class CustomPersonAttributeDao  extends BasePersonAttributeDao {


    @Override
    public PersonAttributes getPerson(String uid, Set<PersonAttributes> resultPeople, PersonAttributeDaoFilter filter) {
        return null;
    }

    @Override
    public Set<PersonAttributes> getPeople(Map<String, Object> query, PersonAttributeDaoFilter filter, Set<PersonAttributes> resultPeople) {
        return null;
    }
}
