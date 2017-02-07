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

import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.common.base.handler.MessageHandlerComparator;
import org.wso2.carbon.identity.mgt.RealmService;

import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.sort;

/**
 * AuthenticationServiceHolder to hold the services.
 */
public class AuthenticationServiceHolder {

    private static AuthenticationServiceHolder authenticationServiceHolder = new AuthenticationServiceHolder();

    private RealmService realmService = null;
    private List<AuthenticationHandler> authenticationHandlers = new ArrayList<>();
    private List<ResourceHandler> resourceHandlers = new ArrayList<>();


    private AuthenticationServiceHolder() {

    }

    public static AuthenticationServiceHolder getInstance() {
        return AuthenticationServiceHolder.authenticationServiceHolder;

    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public void addAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        authenticationHandlers.add(authenticationHandler);
        sort(authenticationHandlers, new MessageHandlerComparator(null));
    }

    public List<ResourceHandler> getResourceHandlers() {
        return resourceHandlers;
    }

    public List<AuthenticationHandler> getAuthenticationHandlers() {
        return authenticationHandlers;
    }
}
