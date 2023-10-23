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
package org.wso2.carbon.identity.authz.valve.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.authz.service.AuthorizationManager;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import java.util.List;
import static java.util.Collections.sort;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;

@Component(
         name = "org.wso2.carbon.identity.authz.valve", 
         immediate = true)
public class AuthorizationValveServiceComponent {

    private static final Log log = LogFactory.getLog(AuthorizationValveServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {
        if (log.isDebugEnabled())
            log.debug("AuthorizationValveServiceComponent is activated");
    }

    @Reference(
             name = "org.wso2.carbon.identity.authz.service.manager.consume", 
             service = org.wso2.carbon.identity.authz.service.AuthorizationManager.class, 
             cardinality = ReferenceCardinality.AT_LEAST_ONE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetAuthorizationManager")
    protected void setAuthorizationManager(AuthorizationManager authorizationManager) {
        if (log.isDebugEnabled()) {
            log.debug("AuthorizationManager acquired");
        }
        List<AuthorizationManager> authorizationManagerList = AuthorizationValveServiceHolder.getInstance().getAuthorizationManagerList();
        authorizationManagerList.add(authorizationManager);
        sort(authorizationManagerList, new HandlerComparator());
    }

    protected void unsetAuthorizationManager(AuthorizationManager authorizationManager) {
        List<AuthorizationManager> authorizationManagerList = AuthorizationValveServiceHolder.getInstance().getAuthorizationManagerList();
        authorizationManagerList.remove(authorizationManager);
    }

    @Reference(
            name = "organization.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        log.debug("Setting the organization management service.");
        AuthorizationValveServiceHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        log.debug("Unset organization management service.");
        AuthorizationValveServiceHolder.getInstance().setOrganizationManager(null);
    }
}

