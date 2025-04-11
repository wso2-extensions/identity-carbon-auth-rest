
/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.utils.logging.CarbonAuditLog;

import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATING_ACTOR;

public class OAuth2AccessTokenHandlerTest {

    private static final Logger log = LoggerFactory.getLogger(OAuth2AccessTokenHandlerTest.class);
    @Mock
    private AuthenticationContext authenticationContext;
    @Mock
    private OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO;
    @Mock
    private AuthenticationRequest authenticationRequest;
    @Mock
    private AuthenticatedUser authenticatedUser;
    @Mock
    private SignedJWT signedJWT;
    @Mock
    private JWTClaimsSet jwtClaimsSet;

    @BeforeClass
    public void setUp() {

        authenticationContext = mock(AuthenticationContext.class);
        oAuth2IntrospectionResponseDTO = mock(OAuth2IntrospectionResponseDTO.class);
        authenticationRequest = mock(AuthenticationRequest.class);
        authenticatedUser = mock(AuthenticatedUser.class);
        signedJWT = mock(SignedJWT.class);
        jwtClaimsSet = mock(JWTClaimsSet.class);
    }

    @DataProvider
    public Object[][] getHandleImpersonatedAccessTokenData() {

        return new Object[][]{
                {"default", "dummyImpersonatingActor", "GET"},
                {"default", "dummyImpersonatingActor", "POST"},
                {"default", "dummyImpersonatingActor", "PUT"},
                {"default", "dummyImpersonatingActor", "DELETE"},
                {"default", "dummyImpersonatingActor", "PATCH"},
                {"default", "dummyImpersonatingActor", "OPTIONS"},
                {"default", "dummyImpersonatingActor", "HEAD"},
                {"default", StringUtils.EMPTY, "GET"},
                {"default", StringUtils.EMPTY, "POST"},
                {"default", StringUtils.EMPTY, "PUT"},
                {"default", StringUtils.EMPTY, "DELETE"},
                {"default", StringUtils.EMPTY, "PATCH"},
                {"default", StringUtils.EMPTY, "OPTIONS"},
                {"default", StringUtils.EMPTY, "HEAD"},
                {OAuth2Constants.TokenTypes.JWT, "dummyImpersonatingActor", "GET"},
                {OAuth2Constants.TokenTypes.JWT, "dummyImpersonatingActor", "POST"},
                {OAuth2Constants.TokenTypes.JWT, "dummyImpersonatingActor", "PUT"},
                {OAuth2Constants.TokenTypes.JWT, "dummyImpersonatingActor", "DELETE"},
                {OAuth2Constants.TokenTypes.JWT, "dummyImpersonatingActor", "PATCH"},
                {OAuth2Constants.TokenTypes.JWT, "dummyImpersonatingActor", "OPTIONS"},
                {OAuth2Constants.TokenTypes.JWT, "dummyImpersonatingActor", "HEAD"},
                {OAuth2Constants.TokenTypes.JWT, StringUtils.EMPTY, "GET"},
                {OAuth2Constants.TokenTypes.JWT, StringUtils.EMPTY, "POST"},
                {OAuth2Constants.TokenTypes.JWT, StringUtils.EMPTY, "PUT"},
                {OAuth2Constants.TokenTypes.JWT, StringUtils.EMPTY, "DELETE"},
                {OAuth2Constants.TokenTypes.JWT, StringUtils.EMPTY, "PATCH"},
                {OAuth2Constants.TokenTypes.JWT, StringUtils.EMPTY, "OPTIONS"},
                {OAuth2Constants.TokenTypes.JWT, StringUtils.EMPTY, "HEAD"},
        };
    }

    @Test(dataProvider = "getHandleImpersonatedAccessTokenData")
    public void testHandleImpersonatedAccessToken(String tokenType, String impersonatingActor, String httpMethod)
            throws Exception {

        String accessToken = "dummyAccessToken";
        String impersonatee = "dummySubjectIdentifier";

        Map<String, Object> introspectionProperties = new HashMap<>();
        introspectionProperties.put(IMPERSONATING_ACTOR, impersonatingActor);

        Map<String, String> mayActClaimSet = new HashMap<>();
        mayActClaimSet.put(Constants.SUB, impersonatingActor);

        when(oAuth2IntrospectionResponseDTO.getTokenType()).thenReturn(tokenType);
        when(oAuth2IntrospectionResponseDTO.getProperties()).thenReturn(introspectionProperties);
        when(oAuth2IntrospectionResponseDTO.getAuthorizedUser()).thenReturn(authenticatedUser);
        when(oAuth2IntrospectionResponseDTO.getClientId()).thenReturn("dummyClientId");
        when(oAuth2IntrospectionResponseDTO.getScope()).thenReturn("dummyScope1, dummyScope2");
        when(authenticatedUser.getAuthenticatedSubjectIdentifier()).thenReturn(impersonatee);
        when(authenticationContext.getAuthenticationRequest()).thenReturn(authenticationRequest);
        when(authenticationRequest.getRequestUri()).thenReturn("dummyRequestUri");
        when(authenticationRequest.getMethod()).thenReturn(httpMethod);

        try (MockedStatic<SignedJWT> mockedStaticSignedJWT = mockStatic(SignedJWT.class);) {

            mockedStaticSignedJWT.when(() -> SignedJWT.parse(accessToken)).thenReturn(signedJWT);
            when(signedJWT.getJWTClaimsSet()).thenReturn(jwtClaimsSet);
            when(jwtClaimsSet.getClaim(Constants.ACT)).thenReturn(mayActClaimSet);

            // Invoke method.
            Class<?> clazz = OAuth2AccessTokenHandler.class;
            Object auth2AccessTokenHandler = clazz.newInstance();
            Method handleImpersonatedAccessToken = auth2AccessTokenHandler.getClass().
                    getDeclaredMethod("handleImpersonatedAccessToken", AuthenticationContext.class, String.class,
                            OAuth2IntrospectionResponseDTO.class);
            handleImpersonatedAccessToken.setAccessible(true);
            handleImpersonatedAccessToken.invoke(auth2AccessTokenHandler,
                    authenticationContext, accessToken, oAuth2IntrospectionResponseDTO);
        } catch (ParseException e) {
            assert false : "Error while parsing the JWT token";
            log.error("Error while parsing the JWT token", e);
        }
    }
}
