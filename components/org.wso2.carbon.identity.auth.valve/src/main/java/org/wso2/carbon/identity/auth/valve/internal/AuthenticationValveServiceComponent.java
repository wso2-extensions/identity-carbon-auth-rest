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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import java.util.List;
import static java.util.Collections.sort;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
         name = "org.wso2.carbon.identity.auth.valve", 
         immediate = true)
public class AuthenticationValveServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticationValveServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationValveServiceComponent is activated");
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
}

