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
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * ClientAuthenticationHandler is for authenticate the request based on Client Authentication.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class ClientAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(ClientAuthenticationHandler.class);
    private final String CLIENT_AUTH_HEADER = "Client";
    private final String hashingFunction = "SHA-256";

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return "ClientAuthentication";
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        return true;
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 130;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null) {
                String authorizationHeader = authenticationContext.getAuthenticationRequest().
                        getHeader(HttpHeaders.AUTHORIZATION);
                if (StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(CLIENT_AUTH_HEADER)
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
        if (splitAuthorizationHeader != null && splitAuthorizationHeader.length == 2) {
            byte[] decodedAuthHeader = Base64.decodeBase64(authorizationHeader.split(" ")[1].getBytes());
            String authHeader = new String(decodedAuthHeader, Charset.defaultCharset());
            String[] splitCredentials = authHeader.split(":");
            if (splitCredentials != null && splitCredentials.length == 2) {
                String appName = splitCredentials[0];
                String password = splitCredentials[1];
                String hash = AuthConfigurationUtil.getInstance().getClientAuthenticationHash(appName);

                if (StringUtils.isNotBlank(hash)) {

                    MessageDigest dgst;
                    try {
                        dgst = MessageDigest.getInstance(hashingFunction);

                        byte[] byteValue = dgst.digest(password.getBytes());

                        //convert the byte to hex format
                        StringBuffer sb = new StringBuffer();
                        for (int i = 0; i < byteValue.length; i++) {
                            sb.append(Integer.toString((byteValue[i] & 0xff) + 0x100, 16).substring(1));
                        }

                        String hashFromRequest = sb.toString();
                        if (hash.equals(hashFromRequest)) {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                            if (log.isDebugEnabled()) {
                                log.debug("ClientAuthentication Success.");
                            }
                        }
                    } catch (NoSuchAlgorithmException e) {
                        String errorMessage = "Error occurred while hashing the app data.";
                        log.error(errorMessage, e);
                        throw new AuthenticationFailException(errorMessage);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No matching application configuration fould for :" + appName);
                    }
                }

            } else {
                String errorMessage = "Error occurred while trying to authenticate and  auth application credentials " +
                        "are not define correctly.";
                log.error(errorMessage);
                throw new AuthClientException(errorMessage);
            }
        } else {
            String errorMessage = "Error occurred while trying to authenticate and  " + HttpHeaders.AUTHORIZATION
                    + " header values are not define correctly.";
            log.error(errorMessage);
            throw new AuthClientException(errorMessage);
        }


        return authenticationResult;
    }

}
