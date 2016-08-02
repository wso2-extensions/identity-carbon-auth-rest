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

/**
 * @scr.component name="org.wso2.carbon.identity.authz.valve" immediate="true"
 * @scr.reference name="org.wso2.carbon.identity.authz.service.manager.consume"
 * interface="org.wso2.carbon.identity.authz.service.AuthorizationManager"
 * cardinality="1..n" policy="dynamic" bind="setAuthorizationManager" unbind="unsetAuthorizationManager"
 */

public class AuthorizationValveServiceComponent {

    private static final Log log = LogFactory.getLog(AuthorizationValveServiceComponent.class);

    protected void activate(ComponentContext cxt) {
        if ( log.isDebugEnabled() )
            log.debug("AuthorizationValveServiceComponent is activated");
    }

    protected void setAuthorizationManager(AuthorizationManager authorizationManager) {
        if ( log.isDebugEnabled() ) {
            log.debug("AuthorizationManager acquired");
        }
        AuthorizationValveServiceHolder.getInstance().getAuthorizationManagerList().add(authorizationManager);
    }

    protected void unsetAuthorizationManager(AuthorizationManager authorizationManager) {
        setAuthorizationManager(null);
    }
}
