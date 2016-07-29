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

package org.wso2.carbon.identity.auth.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.*;
import org.wso2.carbon.identity.auth.service.exception.AuthServiceClientException;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveServiceHolder;
import org.wso2.carbon.identity.core.handler.HandlerManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;


/**
 * AuthenticationValve can be used to intercept any request.
 */
public class AuthenticationValve extends ValveBase {

    private static final String AUTHENTICATED_USER = "authenticated-user";
    private static final String AUTH_HEADER_NAME = "WWW-Authenticate";

    private static final Log log = LogFactory.getLog(AuthenticationValve.class);

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        String requestURI = request.getRequestURI();
        if(log.isDebugEnabled()){
            log.debug("AuthenticationValve hit on " + requestURI);
        }
        if (StringUtils.isNotEmpty(requestURI) && requestURI.startsWith("/api/identity")) {
            AuthenticationResult authenticationResult = null;
            try {
                AuthenticationRequest.AuthenticationRequestBuilder requestBuilder =
                        AuthenticationRequestBuilderFactory.getInstance().createRequestBuilder(request, response);
                AuthenticationContext authenticationContext = new AuthenticationContext(requestBuilder.build());
                List<AuthenticationManager> authenticationManagers =
                        AuthenticationValveServiceHolder.getInstance().getAuthenticationManagers();

                AuthenticationManager authenticationManager = HandlerManager.getInstance().getFirstPriorityHandler(authenticationManagers, true);

                authenticationResult = authenticationManager.authenticate(authenticationContext);
                AuthenticationStatus authenticationStatus = authenticationResult.getAuthenticationStatus();
                if (authenticationStatus.equals(AuthenticationStatus.SUCCESS)) {
                    request.setAttribute(AUTHENTICATED_USER, authenticationResult.getAuthenticatedUser());
                    getNext().invoke(request, response);
                } else {

                    StringBuilder value = new StringBuilder(16);
                    value.append("realm user=\"");
                    if(authenticationResult != null) {
                        value.append(authenticationResult.getAuthenticatedUser());
                    }
                    value.append('\"');
                    response.setHeader(AUTH_HEADER_NAME, value.toString());
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                }
            } catch (AuthServiceClientException e) {
                StringBuilder value = new StringBuilder(16);
                value.append("realm user=\"");
                if(authenticationResult != null) {
                    value.append(authenticationResult.getAuthenticatedUser());
                }
                value.append('\"');
                response.setHeader(AUTH_HEADER_NAME, value.toString());
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
        } else {
            getNext().invoke(request, response);
        }


    }
}
