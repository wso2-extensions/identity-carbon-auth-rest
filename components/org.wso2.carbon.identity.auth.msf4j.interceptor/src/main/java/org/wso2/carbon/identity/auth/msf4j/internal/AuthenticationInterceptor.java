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

package org.wso2.carbon.identity.auth.msf4j.internal;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.service.*;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.messaging.Header;
import org.wso2.msf4j.Interceptor;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.Response;
import org.wso2.msf4j.ServiceMethodInfo;

import java.net.HttpCookie;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ws.rs.core.HttpHeaders;

/**
 *  Authentication Interceptors OSGI ServiceComponent
 */
@Component(
        name = "org.wso2.carbon.identity.auth.msf4j.interceptor",
        immediate = true)
public class AuthenticationInterceptor implements Interceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationInterceptor.class);

    private AuthenticationManager authenticationManager;

    @Activate
    protected void activate(ComponentContext cxt) {
        if (log.isDebugEnabled()) {
            log.debug("AuthenticationValveServiceComponent is activated");
        }
    }

    /**
     * Called by OSGI framework
     * @param authenticationManager  The manager to be set.
     */
    @Reference(
            name = "authenticationManager",
            service = AuthenticationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthenticationManager")
    protected void setAuthenticationManager(AuthenticationManager authenticationManager) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication Manager manager is set to: " + authenticationManager);
        }
        this.authenticationManager = authenticationManager;
    }

    /**
     * Called by OSGI framework.
     * @param authenticationManager The manager to be removed.
     */
    protected void unsetAuthenticationManager(AuthenticationManager authenticationManager) {
        if (this.authenticationManager == authenticationManager) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication Manager manager is removed: ");
            }
            this.authenticationManager = null;
        }
    }

    @Override
    public boolean preCall(Request request, Response response, ServiceMethodInfo serviceMethodInfo) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("PreCall made for the service Method: %s, Path: %s", serviceMethodInfo.getMethod(),
                    request.getUri());
        }
        if (authenticationManager == null) {
            log.error("Authentication Handler manager is not set. Failing the request");
            response.setStatus(javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
            return false;
        }

        AuthenticationRequest.AuthenticationRequestBuilder builder = createRequestBuilder(request, response);
        AuthenticationRequest authenticationRequest = builder.build();
        AuthenticationContext authenticationContext = new AuthenticationContext(authenticationRequest);
        AuthenticationResult authenticationResult = authenticationManager.authenticate(authenticationContext);
        if (authenticationResult.getAuthenticationStatus() == AuthenticationStatus.SUCCESS) {
            /*The authzUser is a workaround since MSF4J does not have proper SecurityContext handling
            * This has to be removed and associate the proper Principal Object to make it similar to
            * JAX-RS way to get the user.*/
            request.setProperty("authzUser", authenticationContext.getUser().getUniqueUserId());
            return true;
        }
        if(authenticationResult.getStatusCode() >0) {
            response.setStatus(authenticationResult.getStatusCode());
        } else {
            response.setStatus(javax.ws.rs.core.Response.Status.UNAUTHORIZED.getStatusCode());
        }

        authenticationResult.getResponseHeaders().stream()
                .forEach(h-> response.setHeader(h.getName(), h.getValue()));

        response.send();
        return false;
    }

    @Override
    public void postCall(Request request, int status, ServiceMethodInfo serviceMethodInfo) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("PostCall made for the service Method: %s, Path: %s", serviceMethodInfo.getMethod(),
                    request.getUri());
        }
    }

    private AuthenticationRequest.AuthenticationRequestBuilder createRequestBuilder(Request request, Response response)
            throws AuthClientException {

        AuthenticationRequest.AuthenticationRequestBuilder authenticationRequestBuilder = new AuthenticationRequest.AuthenticationRequestBuilder();

        if (request.getProperties() != null) {

            Set<String> propertyNames = request.getProperties().keySet();

            for (String propertyName : propertyNames) {

                authenticationRequestBuilder.addAttribute(propertyName, request.getProperty(propertyName));
            }
        }

        if (request.getHeaders() != null && request.getHeaders().getAll() != null) {

            List<Header> headers = request.getHeaders().getAll();

            headers.forEach(header -> authenticationRequestBuilder.addHeader(header.getName(), header.getValue()));

        }

        String cookieHeader = request.getHeader(HttpHeaders.COOKIE);
        List<HttpCookie> cookies = Collections.emptyList();
        if (cookieHeader != null) {
            cookies = HttpCookie.parse(cookieHeader);
        }
        for (HttpCookie cookie : cookies) {
            authenticationRequestBuilder
                    .addCookie(new AuthenticationRequest.CookieKey(cookie.getName(), cookie.getPath()), cookie);
        }
        authenticationRequestBuilder.setContextPath(request.getUri());
        authenticationRequestBuilder.setMethod(request.getHttpMethod());

        return authenticationRequestBuilder;
    }
}
