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

package org.wso2.carbon.identity.authz.service.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.authz.service.AuthorizationManager;
import org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler;
import org.wso2.carbon.identity.authz.service.handler.ResourceHandler;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.wso2.carbon.identity.authz.service" immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="org.wso2.carbon.identity.authz.handler.authz"
 * interface="org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler"
 * cardinality="0..n" policy="dynamic" bind="setAuthorizationHandler" unbind="unsetAuthorizationHandler"
 * @scr.reference name="org.wso2.carbon.identity.authz.handler.resource"
 * interface="org.wso2.carbon.identity.authz.service.handler.ResourceHandler"
 * cardinality="0..n" policy="dynamic" bind="setResourceHandler" unbind="unsetResourceHandler"
 */
public class AuthorizationServiceComponent {

    private static final Log log = LogFactory.getLog(AuthorizationServiceComponent.class);

    protected void activate(ComponentContext cxt) {
        try {
            cxt.getBundleContext().registerService(AuthorizationManager.class, AuthorizationManager.getInstance(),
                    null);
            cxt.getBundleContext().registerService(AuthorizationHandler.class, new AuthorizationHandler(), null);
            if ( log.isDebugEnabled() )
                log.debug("AuthorizationServiceComponent is activated");
        } catch ( Throwable e ) {
            log.error(e.getMessage(), e);
        }

    }

    protected void deactivate(ComponentContext context) {
        if ( log.isDebugEnabled() ) {
            log.debug("AuthorizationServiceComponent bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if ( log.isDebugEnabled() ) {
            log.debug("RealmService acquired");
        }
        AuthorizationServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        setRealmService(null);
    }


    protected void setAuthorizationHandler(AuthorizationHandler authorizationHandler) {
        if ( log.isDebugEnabled() ) {
            log.debug("AuthorizationHandler acquired");
        }
        AuthorizationServiceHolder.getInstance().getAuthorizationHandlerList().add(authorizationHandler);
    }

    protected void unsetAuthorizationHandler(AuthorizationHandler authorizationHandler) {
        setAuthorizationHandler(null);
    }


    protected void setResourceHandler(ResourceHandler resourceHandler) {
        if ( log.isDebugEnabled() ) {
            log.debug("ResourceHandler acquired");
        }
        AuthorizationServiceHolder.getInstance().getResourceHandlerList().add(resourceHandler);
    }

    protected void unsetResourceHandler(ResourceHandler resourceHandler) {
        setResourceHandler(null);
    }





    /*
    protected void addAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationHandler acquired");
        }
        AuthorizationServiceHolder.getInstance().addAuthenticationHandler(authenticationHandler);
    }
    protected void removeAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        AuthorizationServiceHolder.getInstance().getAuthenticationHandlers().remove(authenticationHandler);
    }*/

}
