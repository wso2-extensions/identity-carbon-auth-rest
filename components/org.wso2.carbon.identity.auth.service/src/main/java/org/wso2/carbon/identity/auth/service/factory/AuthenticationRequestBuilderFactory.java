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

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;

import javax.servlet.http.Cookie;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.Enumeration;


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

        Enumeration<String> attributeNames = request.getAttributeNames();
        while ( attributeNames.hasMoreElements() ) {
            String attributeName = attributeNames.nextElement();
            authenticationRequestBuilder.addAttribute(attributeName, request.getAttribute(attributeName));
        }
        authenticationRequestBuilder.addAttribute(HTTPConstants.MC_HTTP_SERVLETREQUEST, request);
        Enumeration<String> headerNames = request.getHeaderNames();
        while ( headerNames.hasMoreElements() ) {
            String headerName = headerNames.nextElement();
            authenticationRequestBuilder.addHeader(headerName, request.getHeader(headerName));
        }
        Cookie[] cookies = request.getCookies();
        if ( cookies != null ) {
            for ( Cookie cookie : cookies ) {
                authenticationRequestBuilder.addCookie(new AuthenticationRequest.CookieKey(cookie.getName(), cookie
                                .getPath()),
                        cookie);
            }
        }
        try {
            authenticationRequestBuilder.setRequestUri(AuthConfigurationUtil.getInstance().
                    getNormalizedRequestURI(request.getRequestURI()));
        } catch (URISyntaxException|UnsupportedEncodingException e) {
            throw new AuthClientException("Error while normalizing url " + request.getRequestURI(), e);
        }
        authenticationRequestBuilder.setContextPath(request.getContextPath());
        authenticationRequestBuilder.setMethod(request.getMethod());
        authenticationRequestBuilder.setRequest(request);

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
