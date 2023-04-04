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
package org.wso2.carbon.identity.auth.service.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.BasicAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.BasicClientAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.ClientAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.ClientCertificateBasedAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.OAuth2AccessTokenHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.TomcatCookieAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;
import org.wso2.carbon.user.core.service.RealmService;
import java.util.Collections;
import java.util.List;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
         name = "org.wso2.carbon.identity.auth.service", 
         immediate = true)
public class AuthenticationServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticationServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {

        ClientAuthenticationHandler clientAuthenticationHandler = new ClientAuthenticationHandler();
        try {
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new BasicAuthenticationHandler(), null);
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new OAuth2AccessTokenHandler(), null);
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new ClientCertificateBasedAuthenticationHandler(), null);
            cxt.getBundleContext().registerService(AuthenticationHandler.class, clientAuthenticationHandler, null);
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new TomcatCookieAuthenticationHandler(), null);
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new BasicClientAuthenticationHandler(), null);
            cxt.getBundleContext().registerService(AuthenticationManager.class, AuthenticationManager.getInstance(), null);
            cxt.getBundleContext().registerService(AuthenticationRequestBuilderFactory.class, AuthenticationRequestBuilderFactory.getInstance(), null);
            AuthConfigurationUtil.getInstance().buildResourceAccessControlData();
            AuthConfigurationUtil.getInstance().buildSkipAuthorizationAllowedEndpointsData();
            AuthConfigurationUtil.getInstance().buildClientAuthenticationHandlerControlData();
            AuthConfigurationUtil.getInstance().buildIntermediateCertValidationConfigData();
            if (log.isDebugEnabled())
                log.debug("AuthenticatorService is activated");
            if (clientAuthenticationHandler.hasDefaultCredentialsUsed()) {
                log.warn("WARNING: Default credentials are being used for the clientAuthenticationHandler " +
                        "which may cause for a potential security vulnerability: WSO2-2020-0864");
            }
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticatorService bundle is deactivated");
        }
    }

    @Reference(
             name = "user.realmservice.default", 
             service = org.wso2.carbon.user.core.service.RealmService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService acquired");
        }
        AuthenticationServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        setRealmService(null);
    }

    @Reference(
             name = "org.wso2.carbon.identity.auth.service.handler.auth", 
             service = org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler.class, 
             cardinality = ReferenceCardinality.MULTIPLE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "removeAuthenticationHandler")
    protected void addAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationHandler acquired");
        }
        AuthenticationServiceHolder.getInstance().addAuthenticationHandler(authenticationHandler);
    }

    protected void removeAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        AuthenticationServiceHolder.getInstance().getAuthenticationHandlers().remove(authenticationHandler);
    }

    @Reference(
             name = "org.wso2.carbon.identity.auth.service.handler.resource", 
             service = org.wso2.carbon.identity.auth.service.handler.ResourceHandler.class, 
             cardinality = ReferenceCardinality.MULTIPLE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "removeResourceHandler")
    protected void addResourceHandler(ResourceHandler resourceHandler) {
        if (log.isDebugEnabled()) {
            log.debug("ResourceHandler acquired");
        }
        List<ResourceHandler> resourceHandlers = AuthenticationServiceHolder.getInstance().getResourceHandlers();
        resourceHandlers.add(resourceHandler);
        Collections.sort(resourceHandlers, new HandlerComparator());
    }

    protected void removeResourceHandler(ResourceHandler resourceHandler) {
        AuthenticationServiceHolder.getInstance().getResourceHandlers().remove(resourceHandler);
    }

    @Reference(
             name = "identityCoreInitializedEventService", 
             service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
            name = "organization.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the organization management service.");
        }
        AuthenticationServiceHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Unset organization management service.");
        }
        AuthenticationServiceHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "organization.user.resident.resolver.service",
            service = OrganizationUserResidentResolverService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserResidentResolverService"
    )
    protected void setOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the organization user resident resolver service.");
        }
        AuthenticationServiceHolder.getInstance().setOrganizationUserResidentResolverService(
                organizationUserResidentResolverService);
    }

    protected void unsetOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset organization user resident resolver service.");
        }
        AuthenticationServiceHolder.getInstance().setOrganizationUserResidentResolverService(null);
    }
}

