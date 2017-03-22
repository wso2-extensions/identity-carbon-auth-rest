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

import org.apache.commons.io.Charsets;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.http.HttpHeaders;
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
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.impl.util.IdentityMgtConstants;

import java.nio.charset.Charset;
import java.util.Base64;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.ws.rs.core.Response;

/**
 * BasicAuthenticationHandler is for authenticate the request based on Basic Authentication.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class BasicAuthenticationHandler extends AbstractAuthenticationHandler {

    private static final Logger log = LoggerFactory.getLogger(BasicAuthenticationHandler.class);
    private static final String BASIC_AUTH_HEADER = "Basic";

    @Override
    public String getName() {
        return "BasicAuthentication";
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 100;
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext)
            throws AuthServerException, AuthClientException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        String authorizationHeader = authenticationContext.getAuthenticationRequest().
                getHeader(HttpHeaders.AUTHORIZATION);

        String[] splitAuthorizationHeader = authorizationHeader.split(" ");
        if (splitAuthorizationHeader.length >= 2) {
            byte[] decodedAuthHeader = Base64.getDecoder()
                    .decode(authorizationHeader.split(" ")[1].getBytes(Charsets.ISO_8859_1));
            String authHeader = new String(decodedAuthHeader, Charset.defaultCharset());
            String[] splitCredentials = authHeader.split(":");
            if (splitCredentials.length >= 2) {
                String userName = splitCredentials[0];
                char[] password = splitCredentials[1] != null ? splitCredentials[1].toCharArray() : new char[0];

                try {
                    ImmutablePair<String, String> domainAndUser = decodeDomainAndUserName(userName);
                    userName = domainAndUser.getLeft();
                    String domainName = domainAndUser.getRight();

                    IdentityStore identityStore = getRealmService().getIdentityStore();

                    //TODO: Related to this https://wso2.org/jira/browse/IDENTITY-4752 - Class IdentityMgtEventListener
                    // : Line 563: Have to check whether why we can't continue
                    //without following lines as previous code.
                    //                    PrivilegedCarbonContext.getCurrentContext()

                    if (identityStore == null) {
                        String errorMessage = "Could not get the identity store to autnenticate the user with "
                                + "BASIC authentication. Username: " + userName;
                        if (log.isDebugEnabled()) {
                            log.debug(errorMessage);
                        }
                        throw new AuthServerException(errorMessage);
                    } else {

                        Claim userNameClaim = new Claim(IdentityMgtConstants.CLAIM_ROOT_DIALECT,
                                IdentityMgtConstants.USERNAME_CLAIM, userName);
                        PasswordCallback passwordCallback = new PasswordCallback("password", false);
                        passwordCallback.setPassword(password);
                        org.wso2.carbon.identity.mgt.AuthenticationContext resultAuthenticationContext = identityStore
                                .authenticate(userNameClaim, new Callback[] { passwordCallback }, domainName);
                        if (resultAuthenticationContext.isAuthenticated()) {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                            authenticationContext.setUser(resultAuthenticationContext.getUser());
                            if (log.isDebugEnabled()) {
                                log.debug("BasicAuthentication success for user: " + userName + " on domain: "
                                        + domainName);
                            }
                        }
                    }
                } catch (AuthenticationFailure authenticationFailure) {
                    if (log.isDebugEnabled()) {
                        log.debug("Authentication failed, with the user: " + userName, authenticationFailure);
                    }
                    return authenticationResult;
                } catch (IdentityStoreException e) {
                    throw new AuthServerException("Error occurred while trying to authenticate user: " + userName, e);
                }
            } else {
                String errorMessage = "Error occurred while trying to authenticate and auth user credentials "
                        + "are not defined correctly.";
                log.error(errorMessage);
                authenticationResult.setAuthenticationStatus(AuthenticationStatus.FAILED);
                authenticationResult.setStatusCode(Response.Status.BAD_REQUEST.getStatusCode());
            }
        } else {
            String errorMessage = "Error occurred while trying to authenticate and  " + HttpHeaders.AUTHORIZATION
                    + " header values are not defined correctly.";
            log.error(errorMessage);
            throw new AuthClientException(errorMessage);
        }

        authenticationResult.addResponseHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic");
        return authenticationResult;
    }

    @Override
    protected String getAuthorizationHeaderType() {
        return BASIC_AUTH_HEADER;
    }
}
