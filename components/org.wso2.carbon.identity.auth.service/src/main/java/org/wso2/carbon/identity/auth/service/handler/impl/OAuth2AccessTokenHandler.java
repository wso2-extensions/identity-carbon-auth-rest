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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * OAuth2AccessTokenHandler is for authenticate the request based on Token.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */

public class OAuth2AccessTokenHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(OAuth2AccessTokenHandler.class);
    private final String OAUTH_HEADER = "Bearer";
    private final String CONSUMER_KEY = "consumer-key";

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        if ( authenticationRequest != null ) {

            String authorizationHeader = authenticationRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if ( StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(OAUTH_HEADER) ) {
                String accessToken = authorizationHeader.split(" ")[1];

                OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();

                token.setIdentifier(accessToken);
                token.setTokenType(OAUTH_HEADER);
                requestDTO.setAccessToken(token);

                //TODO: If these values are not set, validation will fail giving an NPE. Need to see why that happens
                OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                        TokenValidationContextParam();
                contextParam.setKey("dummy");
                contextParam.setValue("dummy");

                OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams =
                        new OAuth2TokenValidationRequestDTO.TokenValidationContextParam[1];
                contextParams[0] = contextParam;
                requestDTO.setContext(contextParams);

                OAuth2ClientApplicationDTO clientApplicationDTO = oAuth2TokenValidationService
                        .findOAuthConsumerIfTokenIsValid
                                (requestDTO);
                OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();

                if ( responseDTO.isValid() ) {
                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                }

                User user = new User();
                user.setUserName(MultitenantUtils.getTenantAwareUsername(responseDTO.getAuthorizedUser()));
                user.setTenantDomain(MultitenantUtils.getTenantDomain(responseDTO.getAuthorizedUser()));
                authenticationContext.setUser(user);

                authenticationContext.addParameter(CONSUMER_KEY, clientApplicationDTO.getConsumerKey());

            }
        }
        return authenticationResult;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return "OAuthAuthentication";
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        return true;
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 25;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        if ( authenticationRequest != null ) {
            String authorizationHeader = authenticationRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if ( StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(OAUTH_HEADER) ) {
                return true;
            }
        }
        return false;
    }


}
