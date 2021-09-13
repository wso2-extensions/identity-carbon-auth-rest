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

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.Charset;

import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;

/**
 * BasicAuthenticationHandler is for authenticate the request based on Basic Authentication.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class BasicAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(BasicAuthenticationHandler.class);
    private final String BASIC_AUTH_HEADER = "Basic";
    private final String USER_NAME = "userName";
    private final String TOTP_ENDPOINT_URI = "api/users/v1/me/totp";

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {

        return "BasicAuthentication";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 100);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        return isAuthHeaderMatch(messageContext, BASIC_AUTH_HEADER);
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) throws AuthenticationFailException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        String authorizationHeader = authenticationContext.getAuthenticationRequest().
                getHeader(HttpHeaders.AUTHORIZATION);

        String[] splitAuthorizationHeader = authorizationHeader.split(" ");
        if (splitAuthorizationHeader.length == 2) {
            byte[] decodedAuthHeader = Base64.decodeBase64(splitAuthorizationHeader[1].getBytes());
            String authHeader = new String(decodedAuthHeader, Charset.defaultCharset());
            String[] splitCredentials = authHeader.split(":", 2);

            if (splitCredentials.length == 2 && StringUtils.isNotBlank(splitCredentials[0]) &&
                    StringUtils.isNotBlank(splitCredentials[1])) {
                String userName = splitCredentials[0];
                String password = splitCredentials[1];

                AbstractUserStoreManager userStoreManager;
                try {
                    int tenantId = IdentityTenantUtil.getTenantIdOfUser(userName);
                    String tenantDomain = MultitenantUtils.getTenantDomain(userName);
                    String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);

                    if (AuthenticationServiceHolder.getInstance().getMultiAttributeLoginService()
                            .isEnabled(tenantDomain)) {
                        ResolvedUserResult resolvedUser = AuthenticationServiceHolder.getInstance()
                                .getMultiAttributeLoginService().resolveUser(tenantAwareUsername, tenantDomain);
                        if (resolvedUser != null && ResolvedUserResult.UserResolvedStatus.SUCCESS.equals(
                                resolvedUser.getResolvedStatus())) {
                            tenantAwareUsername = resolvedUser.getUser().getUsername();
                            userName = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, tenantDomain);
                        } else {
                            String errorMessage = "User does not exists: " + userName;
                            log.error(errorMessage);
                            throw new AuthenticationFailException(errorMessage);
                        }
                    }

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(tenantAwareUsername);
                    user.setTenantDomain(tenantDomain);

                    authenticationContext.setUser(user);

                    //TODO: Related to this https://wso2.org/jira/browse/IDENTITY-4752 - Class IdentityMgtEventListener
                    // : Line 563: Have to check whether why we can't continue
                    //without following lines as previous code.
                    try {
                        PrivilegedCarbonContext.startTenantFlow();
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);

                        UserRealm userRealm = AuthenticationServiceHolder.getInstance().getRealmService().
                                getTenantUserRealm(tenantId);
                        if (userRealm != null) {
                            userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
                            org.wso2.carbon.user.core.common.AuthenticationResult authResult
                                    = userStoreManager.authenticateWithID(UserCoreClaimConstants.USERNAME_CLAIM_URI,
                                    MultitenantUtils.getTenantAwareUsername(userName), password,
                                    UserCoreConstants.DEFAULT_PROFILE);
                            if (org.wso2.carbon.user.core.common.AuthenticationResult.AuthenticationStatus.SUCCESS
                                    == authResult.getAuthenticationStatus()
                                    && authResult.getAuthenticatedUser().isPresent()) {
                                authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                                String domain = UserCoreUtil.getDomainFromThreadLocal();
                                if (StringUtils.isNotBlank(domain)) {
                                    user.setUserStoreDomain(domain);
                                }
                                user.setUserId(authResult.getAuthenticatedUser().get().getUserID());
                                authenticationContext.setUser(user);
                                if (log.isDebugEnabled()) {
                                    log.debug("Basic Authentication successful for the user: " + userName);
                                }
                                MDC.put(USER_NAME, userName);

                                /*
                                If the request is coming to TOTP endpoint, set AuthenticatedWithBasicAuth value to
                                true in the thread local. It will be used in TOTP Service layer to forbid the
                                requests coming with basic auth. This approach can be improved by providing a Level
                                of Assurance (LOA) and checking that in the TOTP service layer.
                                 */
                                if (authenticationRequest.getRequest() != null && authenticationRequest.getRequest()
                                        .getRequestURI().toLowerCase().contains(TOTP_ENDPOINT_URI)) {
                                    IdentityUtil.threadLocalProperties.get()
                                            .put(Constants.AUTHENTICATED_WITH_BASIC_AUTH, "true");
                                }
                            }
                        } else {
                            String errorMessage = "Error occurred while trying to load the user realm for the tenant: " +
                                    tenantId;
                            log.error(errorMessage);
                            throw new AuthenticationFailException(errorMessage);
                        }
                    } finally {
                        PrivilegedCarbonContext.endTenantFlow();
                    }
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    String errorMessage = "Error occurred while trying to authenticate. " + e.getMessage();
                    log.error(errorMessage);
                    throw new AuthenticationFailException(errorMessage);
                }
            } else {
                String errorMessage = "Error occurred while trying to authenticate. The auth user credentials " +
                        "are not defined correctly.";
                log.error(errorMessage);
                throw new AuthenticationFailException(errorMessage);
            }
        } else {
            String errorMessage = "Error occurred while trying to authenticate. The " + HttpHeaders.AUTHORIZATION +
                    " header values are not defined correctly.";
            log.error(errorMessage);
            throw new AuthenticationFailException(errorMessage);
        }
        return authenticationResult;
    }
}
