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
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.BasicAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.OAuthAuthenticationHandler;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.wso2.carbon.identity.auth.service" immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="org.wso2.carbon.identity.auth.service.handler.auth"
 * interface="org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler"
 * cardinality="0..n" policy="dynamic" bind="addAuthenticationHandler" unbind="removeAuthenticationHandler"
 * @scr.reference name="org.wso2.carbon.identity.auth.service.handler.resource"
 * interface="org.wso2.carbon.identity.auth.service.handler.ResourceHandler"
 * cardinality="0..n" policy="dynamic" bind="addResourceHandler" unbind="removeResourceHandler"
 */
public class AuthenticationServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticationServiceComponent.class);

    protected void activate(ComponentContext cxt) {
        try {
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new BasicAuthenticationHandler(), null);
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new OAuthAuthenticationHandler(), null);
            cxt.getBundleContext().registerService(AuthenticationManager.class, AuthenticationManager.getInstance(), null);
            cxt.getBundleContext().registerService(ResourceHandler.class, new ResourceHandler(), null);

            if (log.isDebugEnabled())
                log.debug("AuthenticatorService is activated");
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }

    }

    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticatorService bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService acquired");
        }
        AuthenticationServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        setRealmService(null);
    }

    protected void addAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationHandler acquired");
        }
        AuthenticationServiceHolder.getInstance().addAuthenticationHandler(authenticationHandler);
    }

    protected void removeAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        AuthenticationServiceHolder.getInstance().getAuthenticationHandlers().remove(authenticationHandler);
    }

    protected void addResourceHandler(ResourceHandler resourceHandler) {
        if (log.isDebugEnabled()) {
            log.debug("ResourceHandler acquired");
        }
        AuthenticationServiceHolder.getInstance().getResourceHandlers().add(resourceHandler);
    }

    protected void removeResourceHandler(ResourceHandler resourceHandler) {
        AuthenticationServiceHolder.getInstance().getResourceHandlers().remove(resourceHandler);
    }

}
