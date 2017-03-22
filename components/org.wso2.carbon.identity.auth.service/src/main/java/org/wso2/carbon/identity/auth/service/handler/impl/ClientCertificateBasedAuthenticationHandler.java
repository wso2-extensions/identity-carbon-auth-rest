/*
 *
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   you may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.handler.AbstractAuthenticationHandler;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.User;

/**
 * This authentication handler does the the authentication based on client certificate.
 * The client's' SSL certificate should be verified by the HTTP container.
 * This handler checked whether the certificate is verified by the container.
 * If yes, the value of the 'User' HTTP header will be treated as the authenticated user.
 */
public class ClientCertificateBasedAuthenticationHandler extends AbstractAuthenticationHandler {

    private static final Logger log = LoggerFactory.getLogger(ClientCertificateBasedAuthenticationHandler.class);
    private static final String CLIENT_CERTIFICATE_ATTRIBUTE_NAME = "javax.servlet.request.X509Certificate";
    private static final String USER_HEADER_NAME = "WSO2-Identity-User";

    @Override
    public String getName() {
        return "ClientCertificate";
    }

    public boolean isEnabled(MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null &&
                    authenticationContext.getAuthenticationRequest().
                            getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE_NAME) != null) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected String getAuthorizationHeaderType() {
        return null;
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext)
            throws AuthServerException, AuthClientException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null
                    && authenticationContext.getAuthenticationRequest().
                    getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE_NAME) != null) {

                String username = authenticationContext.getAuthenticationRequest().getHeader(USER_HEADER_NAME);

                if (StringUtils.isNotEmpty(username)) {
                    ImmutablePair<String, String> domainAndUser = decodeDomainAndUserName(username);
                    String domainName = domainAndUser.getRight();
                    username = domainAndUser.getLeft();

                    IdentityStore identityStore = getRealmService().getIdentityStore();

                    User.UserBuilder userBuilder = new User.UserBuilder();
                    userBuilder.setUserId(username);
                    userBuilder.setIdentityStore(identityStore);
                    userBuilder.setDomainName(domainName);

                    authenticationContext.setUser(userBuilder.build());

                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);

                    if (log.isDebugEnabled()) {
                        log.debug(String.format(
                                "Client certificate based authentication was successful. " + "Set '%s' as the user",
                                username));
                    }
                } else {
                    //Server to server authentication. No user involves
                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                }

            }
        }

        return authenticationResult;
    }

}
