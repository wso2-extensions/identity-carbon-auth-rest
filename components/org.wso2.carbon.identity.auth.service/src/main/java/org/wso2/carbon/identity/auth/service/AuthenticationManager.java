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

import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;

/**
 * AuthenticationManager is the manager class for doing the authentication based on the type ex: Basic, Token, etc...
 * This is registered as an OSGi service and can consume as a Service.
 */
public interface AuthenticationManager {

    /**
     * Authenticate the request based on the protocol.
     * AuthenticationContext must have a request object.
     *
     * @param authenticationContext The authentication context to be passed.
     * @return The result of the authentication request.
     * @throws AuthServerException When there is a server-side error in the authentication flow.
     * @throws AuthClientException When there is an error in the request.
     */
    AuthenticationResult authenticate(AuthenticationContext authenticationContext)
            throws AuthServerException, AuthClientException;

    /**
     * Adds a new resource handler.
     * @param resourceHandler The resource Handler being added.
     */
    void addResourceHandler(ResourceHandler resourceHandler);

    /**
     * Removes a Resource handler which was added previously.
     * @param resourceHandler the reference of the Resource handler to be removed.
     */
    void removeResourceHandler(ResourceHandler resourceHandler);

    /**
     * Adds a new authentication handler.
     * @param authenticationHandler The authentication handler to be added
     */
    void addAuthenticationHandler(AuthenticationHandler authenticationHandler);
}
