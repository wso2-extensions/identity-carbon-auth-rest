/*
 * Copyright (c) 2016-2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.authz.service.handler;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.service.internal.AuthorizationServiceHolder;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;

/**
 * AuthorizationHandler can be extended to handle the user permissions.
 */
public class AuthorizationHandler extends AbstractIdentityHandler {
    private static final Log log = LogFactory.getLog(AuthorizationHandler.class);

    private static final String RESOURCE_PERMISSION_NONE = "none";


    /**
     * Handle Authorization.
     *
     * @param authorizationContext
     * @return
     * @throws AuthzServiceServerException
     */
    public AuthorizationResult handleAuthorization(AuthorizationContext authorizationContext)
            throws AuthzServiceServerException {
        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);
        try {
            User user = authorizationContext.getUser();
            String userDomain = user.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(userDomain);
            String permissionString = authorizationContext.getPermissionString();
            String[] allowedScopes = authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES) == null ? null :
                    (String[]) authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES);
            boolean validateScope = authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE) == null ? false :
                    (Boolean) authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE);
            RealmService realmService = AuthorizationServiceHolder.getInstance().getRealmService();
            UserRealm tenantUserRealm = realmService.getTenantUserRealm(tenantId);

            // If the scopes are configured for the API, it gets the first priority
            if (isScopeValidationRequired(authorizationContext, validateScope)) {
                validateScopes(authorizationContext, authorizationResult, allowedScopes);
            }
            if (StringUtils.isNotBlank(permissionString) || authorizationContext.getRequiredScopes().size() == 0) {
                validatePermissions(authorizationResult, user, permissionString, tenantUserRealm);
            }
        } catch (UserStoreException e) {
            String errorMessage = "Error occurred while trying to authorize, " + e.getMessage();
            log.error(errorMessage);
            throw new AuthzServiceServerException(errorMessage, e);
        }
        return authorizationResult;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return "AuthorizationHandler";
    }

    @Override
    public int getPriority() {
        return 100;
    }

    private void validatePermissions(AuthorizationResult authorizationResult, User user, String permissionString, UserRealm tenantUserRealm) throws UserStoreException {

        if (RESOURCE_PERMISSION_NONE.equalsIgnoreCase(permissionString)) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            return;
        }

        AuthorizationManager authorizationManager = tenantUserRealm.getAuthorizationManager();
        boolean isUserAuthorized =
                authorizationManager.isUserAuthorized(UserCoreUtil.addDomainToName(user.getUserName(),
                        user.getUserStoreDomain()), permissionString, CarbonConstants.UI_PERMISSION_ACTION);
        if (isUserAuthorized) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
        }
    }

    private void validateScopes(AuthorizationContext authorizationContext, AuthorizationResult authorizationResult, String[] allowedScopes) {

        boolean granted = true;
        if (allowedScopes != null) {
            for (String scope : authorizationContext.getRequiredScopes()) {
                if (!ArrayUtils.contains(allowedScopes, scope)) {
                    granted = false;
                    break;
                }
            }
            if (granted) {
                authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            }
        }
    }

    private boolean isScopeValidationRequired(AuthorizationContext authorizationContext, boolean validateScope) {

        return validateScope && CollectionUtils.isNotEmpty(authorizationContext.getRequiredScopes());
    }
}
