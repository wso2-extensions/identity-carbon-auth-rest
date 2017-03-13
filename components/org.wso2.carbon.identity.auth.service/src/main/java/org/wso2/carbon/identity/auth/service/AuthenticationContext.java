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

import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.mgt.User;

/**
 * AuthenticationContext which is pass across the authentication flow.
 */
public class AuthenticationContext extends MessageContext {

    private static final long serialVersionUID = 4937506590904486750L;

    private transient AuthenticationRequest authenticationRequest = null;
    private transient AuthenticationResult authenticationResult = null;
    private ResourceConfig resourceConfig = null;
    private User user = null;

    /**
     * Constructor taking the request.
     * @param authenticationRequest  The Authentication request for the context.
     */
    public AuthenticationContext(AuthenticationRequest authenticationRequest) {
        if (authenticationRequest == null) {
            throw new AuthRuntimeException("Constructor failed as AuthenticationRequest parameter can not be null.");
        }
        this.authenticationRequest = authenticationRequest;
    }

    public AuthenticationResult getAuthenticationResult() {
        return authenticationResult;
    }

    public void setAuthenticationResult(AuthenticationResult authenticationResult) {
        this.authenticationResult = authenticationResult;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public ResourceConfig getResourceConfig() {
        return resourceConfig;
    }

    public void setResourceConfig(ResourceConfig resourceConfig) {
        this.resourceConfig = resourceConfig;
    }

    public AuthenticationRequest getAuthenticationRequest() {
        return authenticationRequest;
    }
}
