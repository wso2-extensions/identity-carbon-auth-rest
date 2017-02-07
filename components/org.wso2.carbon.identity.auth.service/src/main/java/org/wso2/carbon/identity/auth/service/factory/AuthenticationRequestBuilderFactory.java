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

package org.wso2.carbon.identity.auth.service.factory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.messaging.Header;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.Response;

import javax.servlet.http.Cookie;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;


/**
 * Request build factory for tomcat valve and other custom types.
 */
public class AuthenticationRequestBuilderFactory extends AbstractIdentityHandler {

    public static final String TENANT_DOMAIN_PATTERN = "/t/([^/]+)";
    private static Log log = LogFactory.getLog(AuthenticationRequestBuilderFactory.class);
    private static AuthenticationRequestBuilderFactory authenticationRequestBuilderFactory = new
            AuthenticationRequestBuilderFactory();

    public static AuthenticationRequestBuilderFactory getInstance() {
        return AuthenticationRequestBuilderFactory.authenticationRequestBuilderFactory;
    }


    /**
     * Tomcat Valve can use this method to create AuthenticationRequest by using connector objects.
     *
     * @param request
     * @param response
     * @return AuthenticationRequest.AuthenticationRequestBuilder
     * @throws AuthClientException
     */
    public AuthenticationRequest.AuthenticationRequestBuilder createRequestBuilder(Request request, Response response)
            throws AuthClientException {

        AuthenticationRequest.AuthenticationRequestBuilder authenticationRequestBuilder = new AuthenticationRequest
                .AuthenticationRequestBuilder();

        if (request.getProperties() != null) {

            Set<String> propertyNames = request.getProperties().keySet();

            for (String propertyName: propertyNames) {

                authenticationRequestBuilder.addAttribute(propertyName, request.getProperty(propertyName));
            }
        }

        if (request.getHeaders() != null && request.getHeaders().getAll() != null) {

            List<Header> headers = request.getHeaders().getAll();

            headers.forEach(header -> authenticationRequestBuilder.addHeader(header.getName(), header.getValue()));

        }

        String cookieHeader = request.getHeader("Cookie");

        if (cookieHeader != null) {
            Arrays.stream(cookieHeader.split(";")).forEach(cookie -> {
                String[] cookieEntry = cookie.split("=", 1);
                authenticationRequestBuilder.addCookie(new AuthenticationRequest.CookieKey(cookieEntry[0], cookie
                                                               .getPath()),
                                                       cookie);
            });
        }
        Cookie[] cookies = request.getCookies();
        if ( cookies != null ) {
            for ( Cookie cookie : cookies ) {
                authenticationRequestBuilder.addCookie(new AuthenticationRequest.CookieKey(cookie.getName(), cookie
                                .getPath()),
                        cookie);
            }
        }
        authenticationRequestBuilder.setContextPath(request.getContextPath());
        authenticationRequestBuilder.setMethod(request.getMethod());

        return authenticationRequestBuilder;
    }


    public boolean canHandle(Request request, Response response) {
        return true;
    }

    @Override
    public int getPriority() {
        return 10;
    }
}
