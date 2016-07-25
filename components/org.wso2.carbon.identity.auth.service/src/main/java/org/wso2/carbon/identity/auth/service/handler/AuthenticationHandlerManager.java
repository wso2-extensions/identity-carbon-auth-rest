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

package org.wso2.carbon.identity.auth.service.handler;


import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.core.handler.MessageHandlerComparator;

import java.util.List;

import static java.util.Collections.sort;

/**
 * HandlerManager is a Utility class.
 *
 */
public class AuthenticationHandlerManager {

    private static AuthenticationHandlerManager authenticationHandlerManager = new AuthenticationHandlerManager();

    public static AuthenticationHandlerManager getInstance() {
        return AuthenticationHandlerManager.authenticationHandlerManager;
    }

    /**
     * Get the list of authentication handlers list.
     *
     * @param authenticationContext
     * @return List<AuthenticationHandler>
     */
    public List<AuthenticationHandler> getAuthenticationHandlerList(AuthenticationContext authenticationContext) {
        List<AuthenticationHandler> authenticationHandlers = AuthenticationServiceHolder.getInstance().getAuthenticationHandlers();
        sort(authenticationHandlers, new MessageHandlerComparator(authenticationContext));
        return authenticationHandlers;
    }
}
