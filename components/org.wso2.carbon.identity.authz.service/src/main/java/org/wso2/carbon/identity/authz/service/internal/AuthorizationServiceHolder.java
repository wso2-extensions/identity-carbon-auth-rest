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

import org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler;
import org.wso2.carbon.identity.authz.service.handler.ResourceHandler;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;


/**
 * AuthorizationServiceHolder to hold the services.
 */
public class AuthorizationServiceHolder {

    private static AuthorizationServiceHolder authenticationServiceHolder = new AuthorizationServiceHolder();

    private List<AuthorizationHandler> authorizationHandlerList = new ArrayList<>();
    private List<ResourceHandler> resourceHandlerList = new ArrayList<>();

    private RealmService realmService = null;
    private OrganizationManager organizationManager;

    private AuthorizationServiceHolder() {

    }

    public static AuthorizationServiceHolder getInstance() {
        return AuthorizationServiceHolder.authenticationServiceHolder;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public List<AuthorizationHandler> getAuthorizationHandlerList() {
        return authorizationHandlerList;
    }

    public List<ResourceHandler> getResourceHandlerList() {
        return resourceHandlerList;
    }

    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }
}
