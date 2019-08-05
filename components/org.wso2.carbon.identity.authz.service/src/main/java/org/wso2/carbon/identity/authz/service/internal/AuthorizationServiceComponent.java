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
import org.wso2.carbon.identity.core.handler.HandlerComparator;
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
         name = "org.wso2.carbon.identity.authz.service", 
         immediate = true)
public class AuthorizationServiceComponent {

    private static final Log log = LogFactory.getLog(AuthorizationServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {
        try {
            cxt.getBundleContext().registerService(AuthorizationManager.class, AuthorizationManager.getInstance(), null);
            cxt.getBundleContext().registerService(AuthorizationHandler.class, new AuthorizationHandler(), null);
            if (log.isDebugEnabled())
                log.debug("AuthorizationServiceComponent is activated");
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("AuthorizationServiceComponent bundle is deactivated");
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
        AuthorizationServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        setRealmService(null);
    }

    @Reference(
             name = "org.wso2.carbon.identity.authz.handler.authz", 
             service = org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler.class, 
             cardinality = ReferenceCardinality.MULTIPLE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetAuthorizationHandler")
    protected void setAuthorizationHandler(AuthorizationHandler authorizationHandler) {
        if (log.isDebugEnabled()) {
            log.debug("AuthorizationHandler acquired");
        }
        List<AuthorizationHandler> authorizationHandlerList = AuthorizationServiceHolder.getInstance().getAuthorizationHandlerList();
        authorizationHandlerList.add(authorizationHandler);
        Collections.sort(authorizationHandlerList, new HandlerComparator());
    }

    protected void unsetAuthorizationHandler(AuthorizationHandler authorizationHandler) {
        setAuthorizationHandler(null);
    }

    @Reference(
             name = "org.wso2.carbon.identity.authz.handler.resource", 
             service = org.wso2.carbon.identity.authz.service.handler.ResourceHandler.class, 
             cardinality = ReferenceCardinality.MULTIPLE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetResourceHandler")
    protected void setResourceHandler(ResourceHandler resourceHandler) {
        if (log.isDebugEnabled()) {
            log.debug("ResourceHandler acquired");
        }
        List<ResourceHandler> resourceHandlerList = AuthorizationServiceHolder.getInstance().getResourceHandlerList();
        resourceHandlerList.add(resourceHandler);
        Collections.sort(resourceHandlerList, new HandlerComparator());
    }

    protected void unsetResourceHandler(ResourceHandler resourceHandler) {
        setResourceHandler(null);
    }
}

