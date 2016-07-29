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

/**
 * @scr.component name="org.wso2.carbon.identity.auth.valve" immediate="true"
 * @scr.reference name="org.wso2.carbon.identity.auth.service.manager"
 * interface="org.wso2.carbon.identity.auth.service.AuthenticationManager"
 * cardinality="1..1" policy="dynamic" bind="setAuthenticationManager" unbind="unsetAuthenticationManager"
 */

public class AuthenticationValveServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticationValveServiceComponent.class);
    protected void activate(ComponentContext cxt) {
        if (log.isDebugEnabled())
            log.debug("AuthenticationValveServiceComponent is activated");
    }

    protected void setAuthenticationManager(AuthenticationManager authenticationManager) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationManager acquired");
        }
        AuthenticationValveServiceHolder.getInstance().getAuthenticationManagers().add(authenticationManager);
    }

    protected void unsetAuthenticationManager(AuthenticationManager authenticationManager) {
        setAuthenticationManager(null);
    }
}
