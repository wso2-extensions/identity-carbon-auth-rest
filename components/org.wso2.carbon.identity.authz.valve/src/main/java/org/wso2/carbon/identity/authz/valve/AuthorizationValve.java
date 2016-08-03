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

package org.wso2.carbon.identity.authz.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationManager;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.valve.internal.AuthorizationValveServiceHolder;
import org.wso2.carbon.identity.core.handler.HandlerManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;


/**
 * AuthenticationValve can be used to intercept any request.
 */
public class AuthorizationValve extends ValveBase {

    private static final String AUTH_HEADER_NAME = "WWW-Authenticate";
    private static final String AUTH_CONTEXT = "auth-context";

    private static final Log log = LogFactory.getLog(AuthorizationValve.class);

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        String requestURI = request.getRequestURI();

        AuthenticationContext authenticationContext = (AuthenticationContext) request.getAttribute(AUTH_CONTEXT);

        if (authenticationContext != null && authenticationContext.getUser() != null && StringUtils.isNotEmpty
                (authenticationContext.getUser()
                .getUserName()) ) {
            ResourceConfig resourceConfig = authenticationContext.getResourceConfig();
            String contextPath = request.getContextPath();
            String httpMethod = request.getMethod();

            AuthorizationContext authorizationContext = new AuthorizationContext();
            if ( resourceConfig != null && StringUtils.isNotEmpty(resourceConfig.getPermissions()) ) {
                authorizationContext.setPermissionString(resourceConfig.getPermissions());
            }

            authorizationContext.setContext(contextPath);
            authorizationContext.setHttpMethods(httpMethod);

            authorizationContext.setUserName(authenticationContext.getUser().getUserName());
            List<AuthorizationManager> authorizationManagerList =
                    AuthorizationValveServiceHolder.getInstance().getAuthorizationManagerList();
            AuthorizationManager authorizationManager = HandlerManager.getInstance().getFirstPriorityHandler
                    (authorizationManagerList, true);
            try {
                AuthorizationResult authorizationResult = authorizationManager.authorize(authorizationContext);
                if ( authorizationResult.getAuthorizationStatus().equals(AuthorizationStatus.GRANT) ) {
                    getNext().invoke(request, response);
                } else {
                    handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_FORBIDDEN);
                }
            } catch ( AuthzServiceServerException e ) {
                handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_BAD_REQUEST);
            }
        } else {
            getNext().invoke(request, response);
        }
    }

    private void handleErrorResponse(AuthenticationContext authenticationContext, Response response, int error) throws
            IOException {
        StringBuilder value = new StringBuilder(16);
        value.append("realm user=\"");
        if ( authenticationContext.getUser() != null ) {
            value.append(authenticationContext.getUser().getUserName());
        }
        value.append('\"');
        response.setHeader(AUTH_HEADER_NAME, value.toString());
        response.sendError(error);
    }
}
