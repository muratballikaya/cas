package com.mb.cas;

import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.authentication.MultifactorAuthenticationProviderSelector;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.services.RegisteredService;
import org.springframework.stereotype.Component;
import java.util.Collection;
@Component
public class CustomMultifactorAuthenticationProviderSelector implements MultifactorAuthenticationProviderSelector {


    @Override
    public MultifactorAuthenticationProvider resolve(Collection<MultifactorAuthenticationProvider> providers, RegisteredService service, Principal principal) throws Throwable {
        if (providers == null || providers.isEmpty()) {
            throw new IllegalArgumentException("No MultifactorAuthenticationProviders available");
        }

        // Example logic: Select the provider with the highest rank
        return providers.stream()
                .sorted((p1, p2) -> Integer.compare(p2.getOrder(), p1.getOrder())) // Sort by order descending
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No suitable MultifactorAuthenticationProvider found"));
    }
}
