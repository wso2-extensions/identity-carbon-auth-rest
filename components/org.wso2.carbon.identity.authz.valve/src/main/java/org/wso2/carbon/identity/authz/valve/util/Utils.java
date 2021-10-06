/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
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
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.List;

public class Utils {

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
        }
        return domain;
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
        return tenantDomainFromURLMapping.equals(tenantDomain);
    }

    /**
     * Checks whether cross-tenant domain is allowed for the tenant.
     *
     * @param authenticationContext Context of the authentication
     * @param authorizationContext  Context of the authorization
     * @return true if the tenant is allowed or if the config is null.
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
