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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.Charset;

/**
 * BasicAuthenticationHandler is for authenticate the request based on Basic Authentication.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class BasicAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(BasicAuthenticationHandler.class);
    private final String BASIC_AUTH_HEADER = "Basic";

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
        if ( messageContext instanceof AuthenticationContext ) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null) {
                String authorizationHeader = authenticationContext.getAuthenticationRequest().
                        getHeader(HttpHeaders.AUTHORIZATION);
                if ( StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(BASIC_AUTH_HEADER)
                        ) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) throws AuthServerException, AuthenticationFailException, AuthClientException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        String authorizationHeader = authenticationContext.getAuthenticationRequest().
                getHeader(HttpHeaders.AUTHORIZATION);

        String[] splitAuthorizationHeader = authorizationHeader.split(" ");
        if ( splitAuthorizationHeader != null && splitAuthorizationHeader.length == 2 ) {
            byte[] decodedAuthHeader = Base64.decodeBase64(authorizationHeader.split(" ")[1].getBytes());
            String authHeader = new String(decodedAuthHeader, Charset.defaultCharset());
            String[] splitCredentials = authHeader.split(":");
            if ( splitCredentials != null && splitCredentials.length == 2 ) {
                String userName = splitCredentials[0];
                String password = splitCredentials[1];


                UserStoreManager userStoreManager = null;
                try {
                    int tenantId = IdentityTenantUtil.getTenantIdOfUser(userName);
                    String tenantDomain = MultitenantUtils.getTenantDomain(userName);

                    User user = new User();
                    user.setUserName(MultitenantUtils.getTenantAwareUsername(userName));
                    user.setTenantDomain(tenantDomain);

                    authenticationContext.setUser(user);


                    //TODO: Related to this https://wso2.org/jira/browse/IDENTITY-4752 - Class IdentityMgtEventListener
                    // : Line 563: Have to check whether why we can't continue
                    //without following lines as previous code.
                    PrivilegedCarbonContext.startTenantFlow();
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);

                    UserRealm userRealm = AuthenticationServiceHolder.getInstance().getRealmService().
                            getTenantUserRealm(tenantId);
                    if ( userRealm != null ) {
                        userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                        boolean isAuthenticated = userStoreManager.authenticate(MultitenantUtils.
                                getTenantAwareUsername(userName), password);
                        if ( isAuthenticated ) {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                            if ( log.isDebugEnabled() ) {
                                log.debug("BasicAuthentication success.");
                            }
                        }

                    } else {
                        String errorMessage = "Error occurred while trying to load the user realm for the tenant.";
                        log.error(errorMessage);
                        throw new AuthenticationFailException(errorMessage);
                    }
                } catch ( org.wso2.carbon.user.api.UserStoreException e ) {
                    String errorMessage = "Error occurred while trying to authenticate, " + e.getMessage();
                    log.error(errorMessage);
                    throw new AuthenticationFailException(errorMessage);
                } finally {
                    PrivilegedCarbonContext.endTenantFlow();
                }
            } else {
                String errorMessage = "Error occurred while trying to authenticate and  auth user credentials " +
                        "are not define correctly.";
                log.error(errorMessage);
                throw new AuthenticationFailException(errorMessage);
            }
        } else {
            String errorMessage = "Error occurred while trying to authenticate and  " + HttpHeaders.AUTHORIZATION
                    + " header values are not define correctly.";
            log.error(errorMessage);
            throw new AuthenticationFailException(errorMessage);
        }


        return authenticationResult;
    }

}
