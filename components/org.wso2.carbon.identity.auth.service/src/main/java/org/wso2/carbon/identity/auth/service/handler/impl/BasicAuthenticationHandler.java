/*
 * Copyright (c) 2016-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.osgi.annotation.bundle.Capability;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailServerException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.compatibility.settings.core.exception.CompatibilitySettingException;
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySetting;
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySettingGroup;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.UserActor;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.compatibility.settings.core.service.CompatibilitySettingsService;

import java.nio.charset.Charset;

import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;

/**
 * BasicAuthenticationHandler is for authenticate the request based on Basic Authentication.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
@Capability(
        namespace = "osgi.service",
        attribute = {
                "objectClass=org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler",
                "service.scope=singleton"
        }
)
public class BasicAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(BasicAuthenticationHandler.class);
    private final String BASIC_AUTH_HEADER = "Basic";
    private final String USER_NAME = "userName";
    private final String TOTP_ENDPOINT_URI = "api/users/v1/me/totp";
    private final String FIDO_ENDPOINT_URI = "api/users/v1/me/webauthn";
    private final String FIDO2_ENDPOINT_URI = "api/users/v2/me/webauthn";
    private final String BACKUP_CODE_ENDPOINT_URI = "api/users/v1/me/backup-code";
    private final String MFA_ENDPOINT_URI = "api/users/v1/me/mfa";
    private final String SCIM2_ME_ENDPOINT_URI = "scim2/me";
    private final String ORGANIZATION_PATH_PARAM = "/o/";
    private final String SCIM2_COMPATIBILITY_SETTING_GROUP = "scim2";
    private final String DISABLE_BASIC_AUTH_FOR_ME_ENDPOINT_CONFIG = "disableBasicAuthForMeEndpoint";

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
                int tenantId;
                String tenantDomain;
                boolean organizationRequest = false;
                try {
                    String requestUri = authenticationRequest.getRequestUri();
                    AuthenticatedUser user = new AuthenticatedUser();
                    if (StringUtils.startsWith(requestUri, ORGANIZATION_PATH_PARAM)) {
                        organizationRequest = true;
                        tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
                        tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
                        String organizationIdFromUsername = getOrganizationIdFromUsername(userName);
                        if (StringUtils.isNotBlank(organizationIdFromUsername)) {
                            String tenantDomainFromUsername = AuthenticationServiceHolder.getInstance()
                                    .getOrganizationManager().resolveTenantDomain(organizationIdFromUsername);
                            if (!StringUtils.equals(tenantDomainFromUsername, tenantDomain)) {
                                tenantId = IdentityTenantUtil.getTenantId(tenantDomainFromUsername);
                                tenantDomain = tenantDomainFromUsername;
                            }
                            user.setUserName(getOrganizationAwareUsername(userName));
                        } else {
                            user.setUserName(userName);
                        }
                        user.setTenantDomain(tenantDomain);
                    } else {
                        tenantId = IdentityTenantUtil.getTenantIdOfUser(userName);
                        tenantDomain = MultitenantUtils.getTenantDomain(userName);
                        user.setUserName(MultitenantUtils.getTenantAwareUsername(userName));
                        user.setTenantDomain(tenantDomain);
                    }

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
                                    organizationRequest ? user.getUserName() :
                                            MultitenantUtils.getTenantAwareUsername(userName),
                                    password, UserCoreConstants.DEFAULT_PROFILE);
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
                                addAuthenticatedUserToIdentityContext(authResult.getAuthenticatedUser().get());

                                /*
                                If the request is coming to TOTP or FIDO2 endpoint, set AuthenticatedWithBasicAuth
                                value to true in the thread local. It will be used in TOTP and FIDO2 Service layers
                                to forbid the requests coming with basic auth. This approach can be improved by
                                providing a Level of Assurance (LOA) and checking that in the TOTP and FIDO2 service
                                layers.
                                 */
                                if (authenticationRequest.getRequest() != null) {
                                    String requestURI = authenticationRequest.getRequest().getRequestURI()
                                            .toLowerCase();

                                    // Block basic authentication for SCIM2 /me endpoint if compatibility config is
                                    // enabled.
                                    if (requestURI.contains(SCIM2_ME_ENDPOINT_URI)) {
                                        blockScim2MeEndpointForBasicAuthIfRequired(requestURI, tenantDomain);
                                    }

                                    if (requestURI.contains(TOTP_ENDPOINT_URI) ||
                                            requestURI.contains(FIDO_ENDPOINT_URI) ||
                                            requestURI.contains(FIDO2_ENDPOINT_URI) ||
                                            requestURI.contains(BACKUP_CODE_ENDPOINT_URI) ||
                                            requestURI.contains(MFA_ENDPOINT_URI)) {
                                        IdentityUtil.threadLocalProperties.get()
                                                .put(Constants.AUTHENTICATED_WITH_BASIC_AUTH, "true");
                                    }
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
                } catch (org.wso2.carbon.user.api.UserStoreException | OrganizationManagementException e) {
                    String errorMessage = "Error occurred while trying to authenticate. " + e.getMessage();
                    log.error(errorMessage);

                    Throwable cause = e.getCause();
                    if (cause instanceof AccountLockException) {
                        String errorCode = ((AccountLockException) cause).getErrorCode();
                        throw new AuthenticationFailException(errorCode, errorMessage);
                    }

                    throw new AuthenticationFailServerException(errorMessage);
                } catch (IdentityRuntimeException e) {
                    if (e.getMessage() != null && e.getMessage().contains("Invalid tenant domain")) {
                        String errorMessage = "Error occurred while trying to authenticate. " +
                                "The tenant domain specified in the username is invalid";
                        throw new AuthenticationFailException(errorMessage, e);
                    }
                    throw e;
                }
            } else {
                String errorMessage = "Error occurred while trying to authenticate. The auth user credentials " +
                        "are not defined correctly.";
                throw new AuthenticationFailException(errorMessage);
            }
        } else {
            String errorMessage = "Error occurred while trying to authenticate. The " + HttpHeaders.AUTHORIZATION +
                    " header values are not defined correctly.";
            throw new AuthenticationFailException(errorMessage);
        }
        return authenticationResult;
    }

    /**
     * Extracts the organization id appended to the username.
     *
     * @param username The username present in the request.
     * @return The organization id extracted from the username. If an organization id is not appended to the username,
     * a null value will be returned.
     */
    private static String getOrganizationIdFromUsername(String username) {

        String userOrgId = null;
        if (username.contains("@") && !MultitenantUtils.isEmailUserName()) {
            userOrgId = username.substring(username.lastIndexOf(64) + 1);
        } else if (MultitenantUtils.isEmailUserName() && username.indexOf("@") != username.lastIndexOf("@")) {
            userOrgId = username.substring(username.lastIndexOf(64) + 1);
        }
        return userOrgId == null ? userOrgId : userOrgId.toLowerCase();
    }

    private static String getOrganizationAwareUsername(String username) {

        if (username.contains("@") && !MultitenantUtils.isEmailUserName()) {
            username = username.substring(0, username.lastIndexOf(64));
        } else if (MultitenantUtils.isEmailUserName()) {
            username = username.substring(0, username.lastIndexOf(64));
        }
        return username;
    }

    private void addAuthenticatedUserToIdentityContext(User user) {

        UserActor userActor = new UserActor.Builder()
                .userId(user.getUserID())
                .username(user.getUsername())
                .build();
        IdentityContext.getThreadLocalIdentityContext().setActor(userActor);
    }

    /**
     * Blocks basic authentication for the scim2/Me endpoint if the compatibility setting is enabled.
     *
     * @param requestURI The request URI to check if it contains the scim2/Me endpoint.
     * @param tenantDomain The tenant domain used to retrieve the compatibility settings.
     * @throws AuthenticationFailException If basic authentication is disabled for the scim2/Me endpoint.
     */
    private void blockScim2MeEndpointForBasicAuthIfRequired(String requestURI, String tenantDomain)
            throws AuthenticationFailException {

        CompatibilitySettingsService compatibilitySettingsService =
                AuthenticationServiceHolder.getInstance().getCompatibilitySettingsService();
        try {
            CompatibilitySetting disabledBasicAuthForMeEndpointCompatibilitySetting =
                    compatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(tenantDomain,
                            SCIM2_COMPATIBILITY_SETTING_GROUP, DISABLE_BASIC_AUTH_FOR_ME_ENDPOINT_CONFIG);

            boolean isDisableBasicAuthForMeEndpoint =
                    Boolean.parseBoolean(
                            disabledBasicAuthForMeEndpointCompatibilitySetting.getCompatibilitySettings()
                                    .get(SCIM2_COMPATIBILITY_SETTING_GROUP)
                                    .getSettingValue(DISABLE_BASIC_AUTH_FOR_ME_ENDPOINT_CONFIG));

            if (isDisableBasicAuthForMeEndpoint) {
                String errorMessage = "Basic authentication is not allowed for scim2/Me endpoint";
                log.debug(errorMessage);
                throw new AuthenticationFailException(errorMessage);
            }
        } catch (CompatibilitySettingException e) {
            log.error(
                    "Error while retrieving compatibility setting for " + DISABLE_BASIC_AUTH_FOR_ME_ENDPOINT_CONFIG,
                    e);
        }
    }
}
