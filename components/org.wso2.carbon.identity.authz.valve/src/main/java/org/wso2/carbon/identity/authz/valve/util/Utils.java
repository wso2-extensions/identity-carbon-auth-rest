/*
 * Copyright (c) 2016-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.authz.valve.util;

import org.apache.catalina.connector.Request;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.valve.internal.AuthorizationValveServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.List;

import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.getResourceResidentTenantForTenantPerspective;

public class Utils {

    private static final Log LOG = LogFactory.getLog(Utils.class);

    public static String getTenantDomainFromURLMapping(Request request) {

        String requestURI = request.getRequestURI();
        String domain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

        if (requestURI.contains("/t/")) {
            String temp = requestURI.substring(requestURI.indexOf("/t/") + 3);
            int index = temp.indexOf('/');
            if (index != -1) {
                temp = temp.substring(0, index);
                domain = temp;
            }
        } else if (requestURI.startsWith("/o/")) {
            domain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        }
        return domain;
    }

    public static String getOrganizationIdFromURLMapping(Request request) {

        String requestURI = request.getRequestURI();
        String organizationId = StringUtils.EMPTY;

        if (requestURI.contains("/o/")) {
            String temp = requestURI.substring(requestURI.indexOf("/o/") + 3);
            int index = temp.indexOf('/');
            if (index != -1) {
                temp = temp.substring(0, index);
                organizationId = temp;
            }
        }
        return organizationId;
    }

    /**
     * Checks whether the tenantDomain from URL mapping and the tenantDomain get from the user name are same.
     *
     * @param authenticationContext Context of the authentication
     * @param request               authentication request
     * @return true if valid request
     */
    public static boolean isUserBelongsToRequestedTenant(AuthenticationContext authenticationContext, Request request) {

        String tenantDomainFromURLMapping = getTenantDomainFromURLMapping(request);
        User user = authenticationContext.getUser();

        String tenantDomain;
        if (user != null) {
            tenantDomain = user.getTenantDomain();
        } else {
            OAuthAppDO oAuthAppDO = (OAuthAppDO) authenticationContext.getProperty(
                    Constants.AUTH_CONTEXT_OAUTH_APP_PROPERTY);
            tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        }

        // If tenant qualified URls are disabled get the requested tenant domain from carbon context
        if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            String tenantDomainFromCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getTenantDomain();
            return tenantDomainFromCarbonContext.equals(tenantDomain);
        }

        if (tenantDomainFromURLMapping.equals(tenantDomain)) {
            return true;
        }

        String appResidentTenant = getResourceResidentTenantForTenantPerspective(authenticationContext.
                getAuthenticationRequest().getRequestUri());
        if (StringUtils.isNotEmpty(appResidentTenant) && StringUtils.equals(appResidentTenant, tenantDomain)) {
            return true;
        }
        // Check request with organization qualified URL is allowed to access.
        String organizationID = getOrganizationIdFromURLMapping(request);
        if (user != null) {
            if (StringUtils.equals(organizationID, ((AuthenticatedUser) user).getAccessingOrganization())) {
                return true;
            } else {
                OAuthAppDO oAuthAppDO = (OAuthAppDO) authenticationContext.getParameter(
                        Constants.AUTH_CONTEXT_OAUTH_APP_PROPERTY);
                tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                String accessingTenantDomain;
                try {
                    accessingTenantDomain = AuthorizationValveServiceHolder.getInstance().getOrganizationManager()
                            .resolveTenantDomain(((AuthenticatedUser) user).getAccessingOrganization());
                } catch (OrganizationManagementException e) {
                    LOG.warn("Unable to resolve tenant domain for organization: "
                            + ((AuthenticatedUser) user).getAccessingOrganization(), e);
                    return false;
                }
                return StringUtils.equals(accessingTenantDomain, tenantDomain);
            }
        }
        return false;
    }

    /**
     * Checks whether cross-tenant-access is allowed for the given tenant.
     *
     * @param authenticationContext Context of the authentication
     * @param authorizationContext  Context of the authorization
     * @return True if the tenant is whitelisted to access the cross-domain.
     */
    public static boolean isTenantBelongsToAllowedCrossTenant(AuthenticationContext authenticationContext,
                                                              AuthorizationContext authorizationContext) {

        User user = authenticationContext.getUser();
        String tenantDomain;
        if (user != null) {
            tenantDomain = user.getTenantDomain();
        } else {
            OAuthAppDO oAuthAppDO =
                    (OAuthAppDO) authenticationContext.getProperty(Constants.AUTH_CONTEXT_OAUTH_APP_PROPERTY);
            tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        }
        List<String> allowedTenants = authorizationContext.getRequiredAllowedTenants();
        if (allowedTenants == null) {
            return true;
        } else {
            return allowedTenants.contains(tenantDomain);
        }
    }
}
