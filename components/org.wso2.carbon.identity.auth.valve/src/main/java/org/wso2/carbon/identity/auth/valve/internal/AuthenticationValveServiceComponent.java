/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.auth.valve.internal;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;
import org.wso2.carbon.identity.core.handler.HandlerComparator;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import static java.util.Collections.sort;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;

@Component(
         name = "org.wso2.carbon.identity.auth.valve", 
         immediate = true)
public class AuthenticationValveServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticationValveServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {

        loadInvalidTenantErrorPage();
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationValveServiceComponent is activated");
        }
    }

    private void loadInvalidTenantErrorPage() {

        try {
            Path invalidTenantDomainHtmlResponse =
                    Paths.get(CarbonUtils.getCarbonHome(), "repository", "resources", "identity", "pages",
                            "invalid_tenant_domain_response.html");
            if (!Files.exists(invalidTenantDomainHtmlResponse) ||
                    !Files.isRegularFile(invalidTenantDomainHtmlResponse)) {
                if (log.isDebugEnabled()) {
                    log.debug("invalidTenantDomainHtmlResponse is not present at: " + invalidTenantDomainHtmlResponse);
                }
            }
            File file = new File(invalidTenantDomainHtmlResponse.toString());
            String errorPage = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
            AuthenticationValveDataHolder.getInstance().setInvalidTenantDomainErrorPage(errorPage);
        } catch (IOException e) {
            log.warn(
                    "File invalid_tenant_domain_response.html not found. The default content will be used as the error page content.");
        }
    }

    @Reference(
             name = "org.wso2.carbon.identity.auth.service.manager", 
             service = org.wso2.carbon.identity.auth.service.AuthenticationManager.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetAuthenticationManager")
    protected void setAuthenticationManager(AuthenticationManager authenticationManager) {
        if (log.isDebugEnabled()) {
            log.debug("Set AuthenticationManager, " + authenticationManager != null ? authenticationManager.getName() : " Unknown");
        }
        List<AuthenticationManager> authenticationManagers = AuthenticationValveServiceHolder.getInstance().getAuthenticationManagers();
        authenticationManagers.add(authenticationManager);
        sort(authenticationManagers, new HandlerComparator());
    }

    protected void unsetAuthenticationManager(AuthenticationManager authenticationManager) {
        if (log.isDebugEnabled()) {
            log.debug("Unset AuthenticationManager, " + authenticationManager != null ? authenticationManager.getName() : " Unknown");
        }
        List<AuthenticationManager> authenticationManagers = AuthenticationValveServiceHolder.getInstance().getAuthenticationManagers();
        authenticationManagers.remove(authenticationManager);
    }

    @Reference(
             name = "org.wso2.carbon.identity.auth.service.factory.auth", 
             service = org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory.class, 
             cardinality = ReferenceCardinality.MULTIPLE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "removeAuthenticationRequestBuilderFactory")
    protected void addAuthenticationRequestBuilderFactory(AuthenticationRequestBuilderFactory requestBuilderFactory) {
        if (log.isDebugEnabled()) {
            log.debug("Set AuthenticationRequestBuilderFactory, " + requestBuilderFactory != null ? requestBuilderFactory.getName() : "Unknown");
        }
        AuthenticationValveServiceHolder.getInstance().getRequestBuilderFactories().add(requestBuilderFactory);
    }

    protected void removeAuthenticationRequestBuilderFactory(AuthenticationRequestBuilderFactory requestBuilderFactory) {
        if (log.isDebugEnabled()) {
            log.debug("Unset AuthenticationRequestBuilderFactory, " + requestBuilderFactory != null ? requestBuilderFactory.getName() : "Unknown");
        }
        AuthenticationValveServiceHolder.getInstance().getRequestBuilderFactories().remove(requestBuilderFactory);
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        AuthenticationValveServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service.");
        }
        AuthenticationValveServiceHolder.getInstance().setRealmService(null);
    }
}

