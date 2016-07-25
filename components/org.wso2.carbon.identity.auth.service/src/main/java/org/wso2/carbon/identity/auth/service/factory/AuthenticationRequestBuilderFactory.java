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

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.exception.AuthServiceClientException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.Cookie;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Request build factory for tomcat valve and other custom types.
 *
 */
public class AuthenticationRequestBuilderFactory {

    private static Log log = LogFactory.getLog(AuthenticationRequestBuilderFactory.class);

    private static AuthenticationRequestBuilderFactory authenticationRequestBuilderFactory = new AuthenticationRequestBuilderFactory();
    public static final String TENANT_DOMAIN_PATTERN = "/t/([^/]+)";

    public static AuthenticationRequestBuilderFactory getInstance() {
        return AuthenticationRequestBuilderFactory.authenticationRequestBuilderFactory;
    }


    /**
     * Tomcat Valve can use this method to create AuthenticationRequest by using connector objects.
     *
     * @param request
     * @param response
     * @return AuthenticationRequest.AuthenticationRequestBuilder
     * @throws AuthServiceClientException
     */
    public AuthenticationRequest.AuthenticationRequestBuilder createRequestBuilder(Request request, Response response)
            throws AuthServiceClientException {

        AuthenticationRequest.AuthenticationRequestBuilder authenticationRequestBuilder = new AuthenticationRequest.AuthenticationRequestBuilder();

        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            authenticationRequestBuilder.addHeader(headerName, request.getHeader(headerName));
        }
        authenticationRequestBuilder.setParameters(request.getParameterMap());
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                authenticationRequestBuilder.addCookie(cookie.getName(), cookie);
            }
        }
        String requestURI = request.getRequestURI();
        Pattern pattern = Pattern.compile(TENANT_DOMAIN_PATTERN);
        Matcher matcher = pattern.matcher(requestURI);
        if (matcher.find()) {
            authenticationRequestBuilder.setTenantDomain(matcher.group(1));
        } else {
            authenticationRequestBuilder.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
        authenticationRequestBuilder.setContentType(request.getContentType());
        authenticationRequestBuilder.setContextPath(request.getContextPath());
        authenticationRequestBuilder.setMethod(request.getMethod());
        authenticationRequestBuilder.setPathInfo(request.getPathInfo());
        authenticationRequestBuilder.setPathTranslated(request.getPathTranslated());
        authenticationRequestBuilder.setQueryString(request.getQueryString());
        authenticationRequestBuilder.setRequestURI(requestURI);
        authenticationRequestBuilder.setRequestURL(request.getRequestURL());
        authenticationRequestBuilder.setServletPath(request.getServletPath());

        return authenticationRequestBuilder;
    }

}
