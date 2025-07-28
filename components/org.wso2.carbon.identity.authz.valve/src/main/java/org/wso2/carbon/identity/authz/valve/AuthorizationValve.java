/*
 * Copyright (c) 2016-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.handler.HandlerManager;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.auth.valve.util.APIErrorResponseHandler;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationManager;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.valve.internal.AuthorizationValveServiceHolder;
import org.wso2.carbon.identity.authz.valve.util.Utils;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.authz.service.OrganizationManagementAuthorizationContext;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.auth.service.util.Constants.ENGAGED_AUTH_HANDLER;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.auth.service.util.Constants.RESOURCE_ORGANIZATION_ID;
import static org.wso2.carbon.identity.auth.service.util.Constants.VALIDATE_LEGACY_PERMISSIONS;

/**
 * AuthenticationValve can be used to intercept any request.
 */
public class AuthorizationValve extends ValveBase {

    private static final String AUTH_CONTEXT = "auth-context";
    private static final String ORGANIZATION_PATH_PARAM = "/o/";

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
            if (!isRequestValidForTenant(authenticationContext, authorizationContext, request)) {
                /*
                Forbidden the /o/<org-id> path requests if the org level authz failed and
                resource is not cross tenant allowed or authenticated user doesn't belong to the accessed resource's org.
                 */
                if (requestURI.startsWith(ORGANIZATION_PATH_PARAM)) {
                    APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                            HttpServletResponse.SC_FORBIDDEN, null);
                    return;
                }
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
                if (resourceConfig != null && resourceConfig.getOperationScopeMap() != null) {
                    Map<String, String> operationScopeMap = new HashMap<>();
                    operationScopeMap = resourceConfig.getOperationScopeMap();
                    authorizationContext.setOperationScopeMap(operationScopeMap);
                }
                String contextPath = request.getContextPath();
                String httpMethod = request.getMethod();
                authorizationContext.setContext(contextPath);
                authorizationContext.setHttpMethods(httpMethod);
                authorizationContext.setUser(authenticationContext.getUser());
                authorizationContext.addParameter(OAUTH2_ALLOWED_SCOPES, authenticationContext.getParameter(OAUTH2_ALLOWED_SCOPES));
                authorizationContext.addParameter(OAUTH2_VALIDATE_SCOPE, authenticationContext.getParameter(OAUTH2_VALIDATE_SCOPE));
                authorizationContext.addParameter(VALIDATE_LEGACY_PERMISSIONS,
                        authenticationContext.getParameter(VALIDATE_LEGACY_PERMISSIONS));
                Pattern patternTenantPerspective = Pattern.compile("^/t/[^/]+/o/[a-f0-9\\-]+?");
                if (patternTenantPerspective.matcher(requestURI).find()) {
                    int startIndex = requestURI.indexOf("/o/") + 3;
                    int endIndex = requestURI.indexOf("/", startIndex);
                    String resourceOrgId = requestURI.substring(startIndex, endIndex);
                    authorizationContext.addParameter(RESOURCE_ORGANIZATION_ID, resourceOrgId);
                }

                String tenantDomainFromURLMapping = Utils.getTenantDomainFromURLMapping(request);
                authorizationContext.setTenantDomainFromURLMapping(tenantDomainFromURLMapping);
                List<AuthorizationManager> authorizationManagerList = AuthorizationValveServiceHolder.getInstance()
                        .getAuthorizationManagerList();
                AuthorizationManager authorizationManager = HandlerManager.getInstance()
                        .getFirstPriorityHandler(authorizationManagerList, true);
                try {
                    AuthorizationResult authorizationResult = authorizationManager.authorize(authorizationContext);
                    if (authorizationResult.getAuthorizationStatus().equals(AuthorizationStatus.GRANT)) {
                        String[] allowedScopes = authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES) == null ? null :
                                (String[]) authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES);
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().setAllowedScopes(List.of(allowedScopes));
                        if (authorizationContext.getUser() instanceof AuthenticatedUser) {
                            String authorizedOrganization = ((AuthenticatedUser)authorizationContext.getUser())
                                    .getAccessingOrganization();
                            // Start tenant flow corresponds to the accessed organization.
                            if (StringUtils.isNotEmpty(authorizedOrganization)) {
                                try {
                                    startOrganizationBoundTenantFlow(authorizedOrganization);
                                    getNext().invoke(request, response);
                                } finally {
                                    PrivilegedCarbonContext.endTenantFlow();
                                    IdentityUtil.threadLocalProperties.get()
                                            .remove(OrganizationManagementConstants.ROOT_TENANT_DOMAIN);
                                }
                            } else {
                                getNext().invoke(request, response);
                            }
                        } else {
                            getNext().invoke(request, response);
                        }
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
        /*
         If no authenticated user or application is not found, and if it is a secured endpoint, check whether endpoint
         is allowed to skip authorization for the engaged auth handler.
         */
        } else if ( authenticationContext != null && authenticationContext.getResourceConfig().isSecured()
                && !isAuthorizationSkipped(authenticationContext.getProperty(
                ENGAGED_AUTH_HANDLER).toString(), request.getRequestURI())) {

            // If not allowed to skip authorization, 403-forbidden response will be received.
            APIErrorResponseHandler.handleErrorResponse(
                    authenticationContext, response, HttpServletResponse.SC_FORBIDDEN, null);
        } else {
            getNext().invoke(request, response);
        }
    }

    private AuthorizationResult authorizeInOrganizationLevel(Request request, Response response,
                                                             AuthenticationContext authenticationContext,
                                                             ResourceConfig resourceConfig) throws IOException {

        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);

        if (!isUserEmpty(authenticationContext)) {
            String httpMethod = request.getMethod();
            String tenantDomainFromURLMapping = Utils.getTenantDomainFromURLMapping(request);

            OrganizationManagementAuthorizationContext orgMgtAuthorizationContext =
                    new OrganizationManagementAuthorizationContext();

            if (resourceConfig != null) {
                if (StringUtils.isNotEmpty(resourceConfig.getPermissions())) {
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
            orgMgtAuthorizationContext.addParameter(VALIDATE_LEGACY_PERMISSIONS,
                    authenticationContext.getParameter(VALIDATE_LEGACY_PERMISSIONS));

            List<AuthorizationManager> authorizationManagerList = AuthorizationValveServiceHolder.getInstance()
                    .getAuthorizationManagerList();
            AuthorizationManager authorizationManager = HandlerManager.getInstance()
                    .getFirstPriorityHandler(authorizationManagerList, true);
            try {
                authorizationResult = authorizationManager.authorize(orgMgtAuthorizationContext);
            } catch (AuthzServiceServerException e) {
                APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null);
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

    /**
     * Checks the endpoint is allowed to skip authorization for the given auth handler.
     *
     * @param authHandlerName   Name of the auth Handler
     * @param requestUri    Request URI
     *
     * @return true if endpoint is allowed to skip authorization.
     */
    private boolean isAuthorizationSkipped(String authHandlerName, String requestUri) {

        String[] authorizationSkipAllowedEndpointConfig = AuthConfigurationUtil.getInstance()
                .getSkipAuthorizationAllowedEndpoints().get(authHandlerName);
        if (authorizationSkipAllowedEndpointConfig == null) {
            return true;
        }

        try {
            String normalizedRequestURI = AuthConfigurationUtil.getInstance().getNormalizedRequestURI(requestUri);

            return Arrays.stream(authorizationSkipAllowedEndpointConfig).anyMatch(
                    endpoint -> Pattern.compile(endpoint).matcher(normalizedRequestURI).matches());
        } catch (URISyntaxException | UnsupportedEncodingException e) {
            throw new AuthRuntimeException("Error normalizing URL path: " + requestUri, e);
        }
    }

    private void startOrganizationBoundTenantFlow(String authorizedOrganization) {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        IdentityUtil.threadLocalProperties.get().put(OrganizationManagementConstants.ROOT_TENANT_DOMAIN, tenantDomain);
        String userId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserId();
        String userName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String userResidentOrganizationId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getUserResidentOrganizationId();
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserId(userId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
        PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .setUserResidentOrganizationId(userResidentOrganizationId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setOrganizationId(authorizedOrganization);
        try {
            String authorizedTenantDomain = getOrganizationManager().resolveTenantDomain(authorizedOrganization);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(authorizedTenantDomain, true);
            populateOrganizationInIdentityContext(authorizedOrganization);
        } catch (OrganizationManagementException e) {
            throw new AuthRuntimeException("Error while resolving tenant domain by organization.", e);
        }
    }

    private void populateOrganizationInIdentityContext(String organizationId) {

        if (IdentityContext.getThreadLocalIdentityContext().getOrganization() != null) {
            log.debug("Organization is already set in the IdentityContext. " +
                    "Skipping initialization of organization.");
            return;
        }

        try {
            MinimalOrganization minimalOrganization = getOrganizationManager().getMinimalOrganization(organizationId,
                    null);

            if (minimalOrganization == null) {
                log.debug("No organization found for the organization id: " + organizationId +
                        ". Cannot initialize organization.");
                return;
            }

            IdentityContext.getThreadLocalIdentityContext().setOrganization(new Organization.Builder()
                    .id(minimalOrganization.getId())
                    .name(minimalOrganization.getName())
                    .organizationHandle(minimalOrganization.getOrganizationHandle())
                    .parentOrganizationId(minimalOrganization.getParentOrganizationId())
                    .depth(minimalOrganization.getDepth())
                    .build());
        } catch (OrganizationManagementException e) {
            log.error("Error while retrieving organization with id: " + organizationId, e);
        }
    }

    private OrganizationManager getOrganizationManager() {

        return AuthorizationValveServiceHolder.getInstance().getOrganizationManager();
    }
}
