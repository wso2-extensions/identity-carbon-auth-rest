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
package org.wso2.carbon.identity.authz.service.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.service.internal.AuthorizationServiceHolder;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;


/**
 * AuthorizationHandler can be extended to handle the user permissions.
 */
public class AuthorizationHandler implements IdentityHandler {
    private static final Log log = LogFactory.getLog(AuthorizationHandler.class);


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
            String userName = authorizationContext.getUserName();
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(userName);
            String permissionString = authorizationContext.getPermissionString();

            RealmService realmService = AuthorizationServiceHolder.getInstance().getRealmService();
            UserRealm tenantUserRealm = realmService.getTenantUserRealm(tenantId);

            AuthorizationManager authorizationManager = tenantUserRealm.getAuthorizationManager();
            boolean isUserAuthorized = authorizationManager.isUserAuthorized(MultitenantUtils.
                            getTenantAwareUsername(userName),
                    permissionString, CarbonConstants.UI_PERMISSION_ACTION);
            if (isUserAuthorized) {
                authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
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
    public boolean isEnabled() {
        return true;
    }

    @Override
    public int getPriority() {
        return 100;
    }
}
