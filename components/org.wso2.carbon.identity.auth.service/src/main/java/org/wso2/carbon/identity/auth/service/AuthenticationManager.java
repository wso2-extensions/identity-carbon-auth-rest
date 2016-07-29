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

package org.wso2.carbon.identity.auth.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.core.handler.HandlerManager;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;

import java.util.List;

/**
 * AuthenticationManager is the manager class for doing the authentication based on the type ex: Basic, Token, etc...
 * <p/>
 * This is registered as an OSGi service and can consume as a Service.
 */
public class AuthenticationManager implements IdentityHandler{

    private static Log log = LogFactory.getLog(AuthenticationManager.class);
    private static AuthenticationManager authenticationManager = new AuthenticationManager();

    public static AuthenticationManager getInstance() {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationManager instance created.");
        }
        return AuthenticationManager.authenticationManager;
    }

    /**
     * This is the method that we can authenticate the request based on the protocol.
     * AuthenticationContext must have a request object.
     *
     * @param authenticationContext
     * @return AuthenticationResult
     */
    public AuthenticationResult authenticate(AuthenticationContext authenticationContext) {
        if (log.isDebugEnabled()) {
            if (authenticationContext != null && authenticationContext.getAuthenticationRequest() != null) {
                AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
                String contextPath = authenticationRequest.getContextPath();
                log.debug("Context Path : " + contextPath + " started to authenticate.");
            }
        }
        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);

        List<AuthenticationHandler> authenticationHandlerList = AuthenticationServiceHolder.getInstance().getAuthenticationHandlers();
        AuthenticationHandler authenticationHandler = HandlerManager.getInstance().getFirstPriorityHandler(authenticationHandlerList, true, authenticationContext);

        if(authenticationHandler != null){
            if (log.isDebugEnabled()) {
                log.debug("AuthenticationHandler found : " + authenticationHandler.getClass().getName() + ".");
            }
            authenticationResult = authenticationHandler.authenticate(authenticationContext);
            if (log.isDebugEnabled()) {
                if (authenticationResult != null) {
                    log.debug("AuthenticationResult : " + authenticationResult.getAuthenticationStatus() + ".");
                }
            }
        }

        return authenticationResult;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return "DefaultAuthenticationManager";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public int getPriority() {
        return 1;
    }
}
