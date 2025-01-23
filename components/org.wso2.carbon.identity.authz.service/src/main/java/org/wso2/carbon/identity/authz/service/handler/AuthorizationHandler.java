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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.service.internal.AuthorizationServiceHolder;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingServiceImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.auth.service.util.Constants.RESOURCE_ORGANIZATION_ID;
import static org.wso2.carbon.identity.auth.service.util.Constants.VALIDATE_LEGACY_PERMISSIONS;

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
            boolean validateLegacyPermissions = authorizationContext.getParameter(VALIDATE_LEGACY_PERMISSIONS) == null ?
                    false : (Boolean) authorizationContext.getParameter(VALIDATE_LEGACY_PERMISSIONS);
            RealmService realmService = AuthorizationServiceHolder.getInstance().getRealmService();
            UserRealm tenantUserRealm = realmService.getTenantUserRealm(tenantId);

            // If the scopes are configured for the API, it gets the first priority
            if (isScopeValidationRequired(authorizationContext, validateScope)) {
                validateScopes(authorizationContext, authorizationResult, allowedScopes);
            } else if (CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
                if (StringUtils.isNotBlank(permissionString) || authorizationContext.getRequiredScopes().size() == 0) {
                    validatePermissions(authorizationResult, user, permissionString, tenantUserRealm);
                }
            } else if (validateLegacyPermissions && StringUtils.isNotBlank(permissionString)) {
                /*
                In some cases, we need to validate the legacy permissions.
                Ex: the /fileupload/ is a rest api that is used only in the carbon management console and it
                requires the legacy permission validation.
                Authenticators will mark when legacy permission validation is required by setting a parameter in the
                context. Ex: TomcatCookieAuthenticationHandler which generally authenticates requests coming from the
                Carbon Management Console.
                 */
                if (log.isDebugEnabled()) {
                    log.debug("Legacy permission validation is engaged for context : " +
                            authorizationContext.getContext());
                }
                validatePermissions(authorizationResult, user, permissionString, tenantUserRealm);
            } else {
                AuthenticatedUser authenticatedUser = new AuthenticatedUser(user);
                String userId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserId();
                // Check whether the user is accessing a resource where the user has the access.
                String resourceOrgId = (String) authorizationContext.getParameter(RESOURCE_ORGANIZATION_ID);
                if (StringUtils.isNotEmpty(resourceOrgId)) {
                    OrganizationUserSharingService organizationUserSharingService = new OrganizationUserSharingServiceImpl();
                    UserAssociation sharedUserAssociation = organizationUserSharingService.
                            getUserAssociationOfAssociatedUserByOrgId(userId, resourceOrgId);
                    if (sharedUserAssociation != null) {
                        authenticatedUser.setAccessingOrganization(sharedUserAssociation.getOrganizationId());
                    }
                }

                if (userId != null) {
                    authenticatedUser.setUserId(userId);
                    boolean isAuthorized = AuthzUtil.isUserAuthorized(authenticatedUser,
                            authorizationContext.getRequiredScopes());
                    if (isAuthorized) {
                        authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
                    }
                }
            }
        } catch (UserStoreException | IdentityOAuth2Exception | OrganizationManagementException e) {
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
