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
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;

/**
 * ClientAuthenticationHandler is for authenticate the request based on Client Authentication.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class ClientAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(ClientAuthenticationHandler.class);
    private final String CLIENT_AUTH_HEADER = "Client";
    private final String hashingFunction = "SHA-256";
    private final String SERVICE_PROVIDER_KEY = "serviceProvider";

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {

        return "ClientAuthentication";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 130);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        return isAuthHeaderMatch(messageContext, CLIENT_AUTH_HEADER);
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) throws AuthenticationFailException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        String authorizationHeader = authenticationContext.getAuthenticationRequest().
                getHeader(HttpHeaders.AUTHORIZATION);
        String serviceProvider =
                authenticationContext.getAuthenticationRequest().getHeader(SERVICE_PROVIDER_KEY.toLowerCase());
        if (StringUtils.isNotEmpty(serviceProvider)) {
            MDC.put(SERVICE_PROVIDER_KEY, serviceProvider);
        }

        String[] splitAuthorizationHeader = authorizationHeader.split(" ");
        if (splitAuthorizationHeader.length == 2) {
            byte[] decodedAuthHeader = Base64.decodeBase64(splitAuthorizationHeader[1].getBytes());
            String authHeader = new String(decodedAuthHeader, Charset.defaultCharset());
            String[] splitCredentials = authHeader.split(":", 2);

            if (splitCredentials.length == 2 && StringUtils.isNotBlank(splitCredentials[0]) &&
                    StringUtils.isNotBlank(splitCredentials[1])) {
                String appName = splitCredentials[0];
                String password = splitCredentials[1];
                String hash = AuthConfigurationUtil.getInstance().getClientAuthenticationHash(appName);

                if (StringUtils.isNotBlank(hash)) {

                    MessageDigest dgst;
                    try {
                        dgst = MessageDigest.getInstance(hashingFunction);

                        byte[] byteValue = dgst.digest(password.getBytes());

                        //convert the byte to hex format
                        StringBuilder sb = new StringBuilder();
                        for (byte b : byteValue) {
                            sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
                        }

                        String hashFromRequest = sb.toString();
                        if (hash.equals(hashFromRequest)) {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                            if (log.isDebugEnabled()) {
                                log.debug("Client Authentication Successful for the application: " + appName);
                            }
                        }
                    } catch (NoSuchAlgorithmException e) {
                        String errorMessage = "Error occurred while hashing the app data.";
                        log.error(errorMessage, e);
                        throw new AuthenticationFailException(errorMessage);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No matching application configuration found for :" + appName);
                    }
                }
            } else {
                String errorMessage = "Error occurred while trying to authenticate. The auth application credentials "
                        + "are not defined correctly.";
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
