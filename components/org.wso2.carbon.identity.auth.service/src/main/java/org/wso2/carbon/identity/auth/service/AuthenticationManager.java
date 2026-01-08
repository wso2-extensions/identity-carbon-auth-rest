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
import org.osgi.annotation.bundle.Capability;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.HandlerManager;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;

import java.util.List;
import java.util.stream.Collectors;

/**
 * AuthenticationManager is the manager class for doing the authentication based on the type ex: Basic, Token, etc...
 * <p/>
 * This is registered as an OSGi service and can consume as a Service.
 */
@Capability(
        namespace = "osgi.service",
        attribute = {
                "objectClass=org.wso2.carbon.identity.auth.service.AuthenticationManager",
                "service.scope=singleton"
        }
)
public class AuthenticationManager implements IdentityHandler {

    private static final Log log = LogFactory.getLog(AuthenticationManager.class);
    private static AuthenticationManager authenticationManager = new AuthenticationManager();

    public static AuthenticationManager getInstance() {
        if ( log.isDebugEnabled() ) {
            log.debug("AuthenticationManager instance created.");
        }
        return AuthenticationManager.authenticationManager;
    }

    public ResourceConfig getSecuredResource(ResourceConfigKey resourceConfigKey) {

        ResourceConfig securedResourceConfig = AuthConfigurationUtil.getInstance().getSecuredConfig(resourceConfigKey);

        if (securedResourceConfig == null) {
            List<ResourceHandler> resourceHandlers =
                    AuthenticationServiceHolder.getInstance().getResourceHandlers();

            for (ResourceHandler resourceHandler : resourceHandlers) {
                securedResourceConfig = resourceHandler.getSecuredResource(resourceConfigKey);
                if (securedResourceConfig != null) {
                    break;
                }
            }
        }
        return securedResourceConfig;
    }

    /**
     * This is the method that we can authenticate the request based on the protocol.
     * AuthenticationContext must have a request object.
     *
     * @param authenticationContext
     * @return AuthenticationResult
     */
    public AuthenticationResult authenticate(AuthenticationContext authenticationContext) throws
            AuthServerException, AuthClientException, AuthenticationFailException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);

        if (authenticationContext != null && authenticationContext.getAuthenticationRequest() != null) {

            if (log.isDebugEnabled()) {
                AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
                String contextPath = authenticationRequest.getContextPath();
                log.debug("Context Path : " + contextPath + " started to authenticate.");
            }

            List<AuthenticationHandler> authenticationHandlerList =
                    AuthenticationServiceHolder.getInstance().getAuthenticationHandlers();

            // Filter authentication handlers engaged for this resource.
            authenticationHandlerList = filterAuthenticationHandlers(authenticationContext, authenticationHandlerList);

            AuthenticationHandler authenticationHandler = HandlerManager.getInstance().getFirstPriorityHandler
                    (authenticationHandlerList, true, authenticationContext);

            if (authenticationHandler == null) {
                throw new AuthenticationFailException("AuthenticationHandler not found.");
            }
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

    /**
     * Filter all available authentication handlers based on the configured 'allowed-auth-handlers' property that
     * defines the handlers that need to be engaged for the particular resource.
     *
     * Eg.
     * <Resource context="(.*)/usermanagement/v1/user/(.*)" http-method="all" secured="true"
     * allowed-auth-handlers="BasicAuthentication,ClientAuthentication"></Resource>
     *
     * In this case only "BasicAuthentication" and "ClientAuthentication" will be engaged for the resource. If
     * 'allowed-auth-handlers' property is not configured we set the default value 'all' which implies all available
     * are engaged to the resource.
     *
     * @param authenticationContext
     * @param handlers
     * @return List of filtered {@link AuthenticationHandler} based on
     */
    private List<AuthenticationHandler> filterAuthenticationHandlers(AuthenticationContext authenticationContext,
                                                                     List<AuthenticationHandler> handlers) {

        ResourceConfig resourceConfig = authenticationContext.getResourceConfig();
        final String allowedAuthHandlers = resourceConfig.getAllowedAuthHandlers();
        final List<String> allowedAuthenticationHandlersForResource =
                AuthConfigurationUtil.getInstance().buildAllowedAuthenticationHandlers(allowedAuthHandlers);

        return handlers.stream()
                .filter(handler -> isHandlerAllowedForResource(allowedAuthenticationHandlersForResource, handler))
                .collect(Collectors.toList());
    }

    private boolean isHandlerAllowedForResource(List<String> allowedAuthenticationHandlersForResource,
                                                AuthenticationHandler handler) {

        return allowedAuthenticationHandlersForResource.contains(handler.getName());
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
