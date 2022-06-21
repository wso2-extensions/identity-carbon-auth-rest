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
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.handler.HandlerManager;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.auth.valve.util.APIErrorResponseHandler;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationManager;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.valve.internal.AuthorizationValveServiceHolder;
import org.wso2.carbon.identity.authz.valve.util.Utils;
import org.wso2.carbon.identity.organization.management.authz.service.OrganizationManagementAuthorizationContext;

import java.io.IOException;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;

/**
 * AuthenticationValve can be used to intercept any request.
 */
public class AuthorizationValve extends ValveBase {

    private static final String AUTH_CONTEXT = "auth-context";

    private static final Log log = LogFactory.getLog(AuthorizationValve.class);

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        AuthenticationContext authenticationContext = (AuthenticationContext) request.getAttribute(AUTH_CONTEXT);
        if (authenticationContext != null &&
                !(isUserEmpty(authenticationContext) && isClientEmpty(authenticationContext))) {
            ResourceConfig resourceConfig = authenticationContext.getResourceConfig();
            AuthorizationContext authorizationContext = new AuthorizationContext();
            if (resourceConfig != null) {
                authorizationContext.setIsCrossTenantAllowed(resourceConfig.isCrossTenantAllowed());
                authorizationContext.setAllowedTenants(resourceConfig.getCrossAccessAllowedTenants());
            }

            String requestURI = request.getRequestURI();
            if (requestURI.startsWith("/o/")) {
                AuthorizationResult authorizationResult =
                        authorizeInOrganizationLevel(request, response, authenticationContext, resourceConfig,
                                authorizationContext);
                /*
                If the user authorized from organization level permissions, grant access and execute next valve.
                 */
                if (AuthorizationStatus.GRANT.equals(authorizationResult.getAuthorizationStatus())) {
                    getNext().invoke(request, response);
                    return;
                }
            }
            // If user didn't authorized via org level authz model, fallback to old authz model.
            if (!isRequestValidForTenant(authenticationContext, authorizationContext, request)) {
                if (log.isDebugEnabled()) {
                    log.debug("Authorization to " + request.getRequestURI()
                            + " is denied because the authenticated user belongs to different tenant domain: "
                            + authenticationContext.getUser().getTenantDomain()
                            + " and cross-domain access for the tenant is disabled.");
                }
                APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                        HttpServletResponse.SC_UNAUTHORIZED, null);
                return;
            }

            if (!isUserEmpty(authenticationContext)) {
                if (resourceConfig != null && StringUtils.isNotEmpty(resourceConfig.getPermissions())) {
                    authorizationContext.setPermissionString(resourceConfig.getPermissions());
                }
                if (resourceConfig != null && CollectionUtils.isNotEmpty(resourceConfig.getScopes())) {
                    authorizationContext.setRequiredScopes(resourceConfig.getScopes());
                }
                String contextPath = request.getContextPath();
                String httpMethod = request.getMethod();
                authorizationContext.setContext(contextPath);
                authorizationContext.setHttpMethods(httpMethod);
                authorizationContext.setUser(authenticationContext.getUser());
                authorizationContext.addParameter(OAUTH2_ALLOWED_SCOPES, authenticationContext.getParameter(OAUTH2_ALLOWED_SCOPES));
                authorizationContext.addParameter(OAUTH2_VALIDATE_SCOPE, authenticationContext.getParameter(OAUTH2_VALIDATE_SCOPE));

                String tenantDomainFromURLMapping = Utils.getTenantDomainFromURLMapping(request);
                authorizationContext.setTenantDomainFromURLMapping(tenantDomainFromURLMapping);
                List<AuthorizationManager> authorizationManagerList = AuthorizationValveServiceHolder.getInstance()
                        .getAuthorizationManagerList();
                AuthorizationManager authorizationManager = HandlerManager.getInstance()
                        .getFirstPriorityHandler(authorizationManagerList, true);
                try {
                    AuthorizationResult authorizationResult = authorizationManager.authorize(authorizationContext);
                    if (authorizationResult.getAuthorizationStatus().equals(AuthorizationStatus.GRANT)) {
                        getNext().invoke(request, response);
                    } else {
                        APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                                HttpServletResponse.SC_FORBIDDEN, null);
                    }
                } catch (AuthzServiceServerException e) {
                    APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                            HttpServletResponse.SC_BAD_REQUEST, null);
                }
            } else {
                getNext().invoke(request, response);
            }
        } else {
            getNext().invoke(request, response);
        }
    }

    private AuthorizationResult authorizeInOrganizationLevel(Request request, Response response,
                                              AuthenticationContext authenticationContext,
                                              ResourceConfig resourceConfig, AuthorizationContext authorizationContext)
            throws IOException {

        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);

        if (!isUserEmpty(authenticationContext)) {
            String httpMethod = request.getMethod();
            String tenantDomainFromURLMapping = Utils.getTenantDomainFromURLMapping(request);

            OrganizationManagementAuthorizationContext orgMgtAuthorizationContext =
                    new OrganizationManagementAuthorizationContext();

            if (resourceConfig != null) {
                if(StringUtils.isNotEmpty(resourceConfig.getPermissions())) {
                    orgMgtAuthorizationContext.setPermissionString(resourceConfig.getPermissions());
                }
                if (CollectionUtils.isNotEmpty(resourceConfig.getScopes())) {
                    orgMgtAuthorizationContext.setRequiredScopes(resourceConfig.getScopes());
                }
                orgMgtAuthorizationContext.setContext(resourceConfig.getContext());
            }
            orgMgtAuthorizationContext.setHttpMethods(httpMethod);
            orgMgtAuthorizationContext.setUser(authenticationContext.getUser());
            orgMgtAuthorizationContext.setTenantDomainFromURLMapping(tenantDomainFromURLMapping);
            orgMgtAuthorizationContext.addParameter(OAUTH2_ALLOWED_SCOPES,
                    authenticationContext.getParameter(OAUTH2_ALLOWED_SCOPES));
            orgMgtAuthorizationContext.addParameter(OAUTH2_VALIDATE_SCOPE,
                    authenticationContext.getParameter(OAUTH2_VALIDATE_SCOPE));

            List<AuthorizationManager> authorizationManagerList = AuthorizationValveServiceHolder.getInstance()
                    .getAuthorizationManagerList();
            AuthorizationManager authorizationManager = HandlerManager.getInstance()
                    .getFirstPriorityHandler(authorizationManagerList, true);
            try {
                authorizationResult = authorizationManager.authorize(orgMgtAuthorizationContext);
            } catch (AuthzServiceServerException e) {
                APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                        HttpServletResponse.SC_BAD_REQUEST, null);
            }
        }
        return authorizationResult;
    }

    /**
     * Checks the request is valid for Tenant.
     *
     * @param authenticationContext Context of the authentication
     * @param authorizationContext  Context of the authorization
     * @param request               authentication request
     * @return true if valid request
     */
    private boolean isRequestValidForTenant(AuthenticationContext authenticationContext,
                                            AuthorizationContext authorizationContext, Request request) {

        return (Utils.isUserBelongsToRequestedTenant(authenticationContext, request) ||
                (authorizationContext.isCrossTenantAllowed()) &&
                        Utils.isTenantBelongsToAllowedCrossTenant(authenticationContext, authorizationContext));
    }

    private boolean isUserEmpty(AuthenticationContext authenticationContext) {

        return (authenticationContext.getUser() == null ||
                StringUtils.isEmpty(authenticationContext.getUser().getUserName()));
    }

    private boolean isClientEmpty(AuthenticationContext authenticationContext) {

        return authenticationContext.getProperty(Constants.AUTH_CONTEXT_OAUTH_APP_PROPERTY) == null;
    }
}
