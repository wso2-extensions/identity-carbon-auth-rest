/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.handler.AbstractAuthenticationManager;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.common.base.handler.HandlerComparator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Default implementation for the authentication manager.
 *
 */
public class DefaultAuthenticationManager extends AbstractAuthenticationManager {

    private static Logger log = LoggerFactory.getLogger(DefaultAuthenticationManager.class);

    private Map<String, String> applicationConfigMap = new HashMap<>();
    private List<ResourceHandler> resourceHandlers = new ArrayList<>();

    @Override
    public AuthenticationResult authenticate(AuthenticationContext authenticationContext)
            throws AuthServerException, AuthClientException {

        if (log.isDebugEnabled()) {
            logAuthenticationStart(authenticationContext);
        }

        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        ResourceConfigKey resourceConfigKey = new ResourceConfigKey(authenticationRequest.getContextPath(),
                authenticationRequest.getMethod());
        ResourceConfig securedResource = getSecuredResource(resourceConfigKey);

        if (securedResource == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find any ResourceAccessControl element for the method: %s, URI: %s  "
                                + "Failing the authentication", resourceConfigKey.getContextPath(),
                        resourceConfigKey.getHttpMethod());
            }
            return new AuthenticationResult(AuthenticationStatus.FAILED);
        }

        if (!securedResource.isSecured()) {
            return new AuthenticationResult(AuthenticationStatus.NOTSECURED);
        }

        authenticationContext.setResourceConfig(securedResource);
        AuthenticationHandler authenticationHandler = getFirstPriorityAuthenticationHandler(true,
                authenticationContext);

        if (authenticationHandler == null) {
            throw new AuthRuntimeException(String.format("AuthenticationHandler to handle the request not found."
                            + "Request details are, method: %s, URI: %s", authenticationRequest.getMethod(),
                    authenticationRequest.getContextPath()));
        }
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationHandler found : " + authenticationHandler.getClass().getName() + ".");
        }
        AuthenticationResult authenticationResult = authenticationHandler.authenticate(authenticationContext);
        authenticationContext.setAuthenticationResult(authenticationResult);

        if (log.isDebugEnabled()) {
            if (authenticationResult != null) {
                log.debug("AuthenticationResult : " + authenticationResult.getAuthenticationStatus() + ".");
            }
        }

        return authenticationResult;
    }

    @Override
    public void addResourceHandler(ResourceHandler resourceHandler) {
        resourceHandlers.add(resourceHandler);
        Collections.sort(resourceHandlers, new HandlerComparator());
    }

    @Override
    public void removeResourceHandler(ResourceHandler resourceHandler) {
        resourceHandlers.remove(resourceHandler);
    }

    protected ResourceConfig getSecuredResource(ResourceConfigKey resourceConfigKey) {
        return resourceHandlers.stream().map(h -> h.getSecuredResource(resourceConfigKey)).filter(r -> r != null)
                .findAny().orElse(null);
    }

    private void logAuthenticationStart(AuthenticationContext authenticationContext) {
        if (authenticationContext != null && authenticationContext.getAuthenticationRequest() != null) {
            AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
            String contextPath = authenticationRequest.getContextPath();
            log.debug("Context Path : " + contextPath + " started to authenticate.");
        }
    }
}
