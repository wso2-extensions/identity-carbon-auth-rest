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
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.handler.AbstractAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.common.base.message.MessageContext;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * ClientAuthenticationHandler is for authenticate the request based on Client Authentication.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class ClientAuthenticationHandler extends AbstractAuthenticationHandler {

    private static final Logger log = LoggerFactory.getLogger(ClientAuthenticationHandler.class);
    private static final String CLIENT_AUTH_HEADER = "Client";
    private static final String HASHING_FUNCTION = "SHA-256";

    @Override
    public String getName() {
        return "ClientAuthentication";
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 130;
    }

    @Override
    protected String getAuthorizationHeaderType() {
        return CLIENT_AUTH_HEADER;
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext)
            throws AuthServerException, AuthClientException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        String authorizationHeader = authenticationContext.getAuthenticationRequest().
                getHeader(HttpHeaders.AUTHORIZATION);

        String[] splitAuthorizationHeader = authorizationHeader.split(" ");
        if (splitAuthorizationHeader.length == 2) {
            byte[] decodedAuthHeader = Base64.getDecoder()
                    .decode(authorizationHeader.split(" ")[1].getBytes(Charsets.ISO_8859_1));
            String authHeader = new String(decodedAuthHeader, Charset.defaultCharset());
            String[] splitCredentials = authHeader.split(":");
            if (splitCredentials.length == 2) {
                String appName = splitCredentials[0];
                String password = splitCredentials[1];
                String hash = AuthConfigurationUtil.getInstance().getClientAuthenticationHash(appName);

                if (StringUtils.isNotBlank(hash)) {

                    MessageDigest dgst;
                    try {
                        dgst = MessageDigest.getInstance(HASHING_FUNCTION);

                        byte[] byteValue = dgst.digest(password.getBytes(Charsets.ISO_8859_1));

                        String hashFromRequest = encodeHexString(byteValue);
                        if (hash.equals(hashFromRequest)) {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                            if (log.isDebugEnabled()) {
                                log.debug("ClientAuthentication Success.");
                            }
                        }
                    } catch (NoSuchAlgorithmException e) {
                        String errorMessage = "Error occurred while hashing the app data.";
                        log.error(errorMessage, e);
                        throw new AuthServerException(errorMessage);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No matching application configuration found for :" + appName);
                    }
                }

            } else {
                String errorMessage = "Error occurred while trying to authenticate and  auth application credentials "
                        + "are not define correctly.";
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

    private String encodeHexString(byte[] byteValue) {
        return javax.xml.bind.DatatypeConverter.printHexBinary(byteValue);
    }

}
