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
package org.wso2.carbon.identity.authz.service;


import org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler;
import org.wso2.carbon.identity.authz.service.handler.ResourceHandler;
import org.wso2.carbon.identity.authz.service.internal.AuthorizationServiceHolder;
import org.wso2.carbon.identity.core.handler.HandlerManager;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;


import java.util.List;

public class AuthorizationManager implements IdentityHandler{

    private static AuthorizationManager authorizationManager = new AuthorizationManager();

    private AuthorizationManager(){}

    public static AuthorizationManager getInstance(){
        return AuthorizationManager.authorizationManager ;
    }

    public AuthorizationResult authorize(AuthorizationContext authorizationContext){

        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);

        List<ResourceHandler> resourceHandlerList =
                AuthorizationServiceHolder.getInstance().getResourceHandlerList();
        List<ResourceHandler> resourceHandlers = HandlerManager.getInstance().sortHandlers(resourceHandlerList, true);
        for(ResourceHandler resourceHandler: resourceHandlers){
            boolean isResourceFound = resourceHandler.handleResource(authorizationContext);
            if(isResourceFound){
                break ;
            }
        }
        List<AuthorizationHandler> authorizationHandlerList = AuthorizationServiceHolder.getInstance().getAuthorizationHandlerList();
        AuthorizationHandler authorizationHandler = HandlerManager.getInstance().getFirstPriorityHandler(authorizationHandlerList, true);
        authorizationResult = authorizationHandler.handleAuthorization(authorizationContext);


        return authorizationResult ;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public int getPriority() {
        return 0;
    }
}
