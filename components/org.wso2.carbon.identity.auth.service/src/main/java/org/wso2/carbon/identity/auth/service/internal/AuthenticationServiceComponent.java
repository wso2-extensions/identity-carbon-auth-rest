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

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.AbstractAuthenticationManager;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.*;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.common.base.handler.InitConfig;
import org.wso2.carbon.identity.mgt.RealmService;

import java.util.ArrayList;
import java.util.List;

/**
 *  Authentication Service OSGI Component
 */
@Component(
        name = "org.wso2.carbon.identity.auth.service",
        immediate = true,
        property = {
                "componentName=wso2-carbon-identity-rest-auth"
        })
public class AuthenticationServiceComponent {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationServiceComponent.class);
    private List<AuthenticationHandler> ownAuthenticationHandlers = new ArrayList<>();
    private RealmService realmService;
    private DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager();

    @Activate
    protected void activate(ComponentContext cxt) {
        DefaultResourceHandler defaultResourceHandler = new DefaultResourceHandler();
        defaultResourceHandler.init(new InitConfig());
        addResourceHandler(defaultResourceHandler);

        ownAuthenticationHandlers.add(new BasicAuthenticationHandler());
        ownAuthenticationHandlers.add(new OAuth2AccessTokenHandler());
        ownAuthenticationHandlers.add(new ClientCertificateBasedAuthenticationHandler());
        ownAuthenticationHandlers.add(new ClientAuthenticationHandler());

        ownAuthenticationHandlers.stream().forEach(h -> h.setRealmService(realmService));
        ownAuthenticationHandlers.stream()
                .forEach(h -> authenticationManager.addAuthenticationHandler(h));

        cxt.getBundleContext()
                .registerService(AuthenticationManager.class, authenticationManager, null);

        AuthConfigurationUtil.getInstance().buildResourceAccessControlData();
        AuthConfigurationUtil.getInstance().buildClientAuthenticationHandlerControlData();

        if (log.isDebugEnabled()) {
            log.debug("AuthenticatorService is activated");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticatorService bundle is deactivated");
        }
    }

    @Reference(
            name = "realmService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService acquired");
        }
        this.realmService = realmService;
        ownAuthenticationHandlers.stream().forEach(h -> h.setRealmService(realmService));
    }

    protected void unsetRealmService(RealmService realmService) {
        setRealmService(null);
    }

    @Reference(
            name = "authenticationHandler",
            service = AuthenticationHandler.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeAuthenticationHandler")
    protected void addAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationHandler acquired");
        }
        authenticationManager.addAuthenticationHandler(authenticationHandler);
    }

    protected void removeAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        authenticationManager.removeAuthenticationHandler(authenticationHandler);
    }

    @Reference(
            name = "resourceHandler",
            service = ResourceHandler.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeResourceHandler")
    protected void addResourceHandler(ResourceHandler resourceHandler) {
        if (log.isDebugEnabled()) {
            log.debug("ResourceHandler acquired");
        }
        authenticationManager.addResourceHandler(resourceHandler);

    }

    protected void removeResourceHandler(ResourceHandler resourceHandler) {
        authenticationManager.removeResourceHandler(resourceHandler);
    }
}
