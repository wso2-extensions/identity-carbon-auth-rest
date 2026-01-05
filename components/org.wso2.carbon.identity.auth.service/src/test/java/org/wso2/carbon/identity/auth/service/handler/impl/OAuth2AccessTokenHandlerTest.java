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
import org.apache.catalina.connector.Request;
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
import org.testng.Assert;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
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

    @DataProvider
    public Object[][] getCanHandleCaseSensitivityTestData() {
        return new Object[][]{
                // Test case 1: "Bearer" with capital B - should return true (case insensitive)
                {"Bearer", true},
                // Test case 2: "bearer" with lowercase b - should return true (case insensitive)  
                {"bearer", true},
                // Test case 3: "BEARER" all uppercase - should return true (case insensitive)
                {"BEARER", true},
                // Test case 4: "Basic" auth header - should return false
                {"Basic", false},
                // Test case 5: "Token" auth header - should return false
                {"Token", false},
                // Test case 6: Empty string - should return false
                {"", false},
                // Test case 7: null header - should return false
                {null, false},
                // Test case 8: Random string - should return false
                {"RandomAuth", false},
        };
    }

    @Test(dataProvider = "getCanHandleCaseSensitivityTestData")
    public void testCanHandleWithDifferentAuthHeaders(String authHeaderIdentifier, boolean expectedResult) throws Exception {

        OAuth2AccessTokenHandler oAuth2AccessTokenHandler = new OAuth2AccessTokenHandler();
        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);

        try (MockedStatic<AuthConfigurationUtil> mockedAuthConfigUtil = mockStatic(AuthConfigurationUtil.class)) {
            
            // Mock the static method call - simulate the actual behavior of isAuthHeaderMatch
            boolean mockResult = authHeaderIdentifier != null && 
                                (authHeaderIdentifier.equalsIgnoreCase("Bearer"));
            
            mockedAuthConfigUtil.when(() -> AuthConfigurationUtil.isAuthHeaderMatch(
                    authenticationContext, "Bearer", false))
                    .thenReturn(mockResult);

            // Test the canHandle method
            boolean result = oAuth2AccessTokenHandler.canHandle(authenticationContext);

            // Verify the result
            Assert.assertEquals(result, expectedResult, 
                "Expected " + expectedResult + " for auth header: " + authHeaderIdentifier);
            
            // Verify that isAuthHeaderMatch was called with correct parameters
            mockedAuthConfigUtil.verify(() -> AuthConfigurationUtil.isAuthHeaderMatch(
                    authenticationContext, "Bearer", false));
        }
    }

    @DataProvider
    public Object[][] signedJWTProvider() throws ParseException {

        String tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0." +
                "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        SignedJWT signedJWT = SignedJWT.parse(tokenString);
        return new Object[][]{
                {signedJWT}
        };
    }

    @Test(dataProvider = "signedJWTProvider")
    public void getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        OAuth2AccessTokenHandler oAuth2AccessTokenHandler = new OAuth2AccessTokenHandler();
        JWTClaimsSet jwtClaimsSet = oAuth2AccessTokenHandler.getClaimSet(signedJWT);
        Assert.assertNotNull(jwtClaimsSet, "JWT Claim Set is null");
    }

    @DataProvider
    public Object[][] isTokenBindingValidDataProvider() {

        return new Object[][]{
                // Test case 1: Valid token binding, validation enabled, binding valid - should return true
                {"bindingRef123", "clientId", "accessToken", "tenantDomain", true, "Valid token binding"},

                // Test case 2: Valid token binding, validation enabled, binding invalid - should return false
                {"bindingRef123", "clientId", "accessToken", "tenantDomain", false, "Invalid token binding"},

                // Test case 3: Token binding with organization tenant domain - should handle properly
                {"bindingRef123", "clientId", "accessToken", "org1", true, "Organization tenant domain"},
        };
    }

    @Test(dataProvider = "isTokenBindingValidDataProvider")
    public void testIsTokenBindingValid(String bindingReference, String clientId, String accessToken,
                                       String tenantDomain, boolean expectedResult, String testCase) throws Exception {

        OAuth2AccessTokenHandler oAuth2AccessTokenHandler = new OAuth2AccessTokenHandler();

        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        AuthenticationRequest authenticationRequest = mock(AuthenticationRequest.class);
        Request request = mock(Request.class);
        OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);
        TokenBinding tokenBinding = bindingReference != null && !bindingReference.isEmpty()
                ? new TokenBinding("cookie", bindingReference, "value")
                : null;

        when(authenticationContext.getAuthenticationRequest()).thenReturn(authenticationRequest);
        when(authenticationRequest.getRequest()).thenReturn(request);
        when(request.getRequestURI()).thenReturn("/api/users/v1/me");
        when(oAuthAppDO.getApplicationName()).thenReturn("TestApp");

        // Configure token binding validation based on test case
        if ("Valid token binding".equals(testCase)) {
            when(oAuthAppDO.isTokenBindingValidationEnabled()).thenReturn(true);
        } else if ("Invalid token binding".equals(testCase)) {
            when(oAuthAppDO.isTokenBindingValidationEnabled()).thenReturn(true);
        } else if ("Validation disabled".equals(testCase)) {
            when(oAuthAppDO.isTokenBindingValidationEnabled()).thenReturn(false);
        } else {
            when(oAuthAppDO.isTokenBindingValidationEnabled()).thenReturn(false);
        }

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<OrganizationManagementUtil> mockedOrgMgmtUtil =
                     mockStatic(OrganizationManagementUtil.class)) {

            // Mock organization check
            if (StringUtils.isNotBlank(tenantDomain) && "org1".equals(tenantDomain)) {
                mockedOrgMgmtUtil.when(() -> OrganizationManagementUtil.isOrganization(tenantDomain))
                        .thenReturn(true);
                mockedOAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(clientId, tenantDomain))
                        .thenReturn(oAuthAppDO);
            } else {
                if (StringUtils.isNotBlank(tenantDomain)) {
                    mockedOrgMgmtUtil.when(() -> OrganizationManagementUtil.isOrganization(tenantDomain))
                            .thenReturn(false);
                }
                mockedOAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(clientId))
                        .thenReturn(oAuthAppDO);
            }

            // Mock token binding validation
            if ("Valid token binding".equals(testCase)) {
                mockedOAuth2Util.when(() -> OAuth2Util.isValidTokenBinding(any(TokenBinding.class),
                                any(Request.class))).thenReturn(true);
            } else if ("Invalid token binding".equals(testCase)) {
                mockedOAuth2Util.when(() -> OAuth2Util.isValidTokenBinding(any(TokenBinding.class),
                                any(Request.class))).thenReturn(false);
            }

            // Invoke the private method using reflection
            Method isTokenBindingValidMethod = oAuth2AccessTokenHandler.getClass()
                    .getDeclaredMethod("isTokenBindingValid", MessageContext.class, TokenBinding.class,
                            String.class, String.class, String.class);
            isTokenBindingValidMethod.setAccessible(true);

            boolean result = (boolean) isTokenBindingValidMethod.invoke(oAuth2AccessTokenHandler,
                    authenticationContext, tokenBinding, clientId, accessToken, tenantDomain);

            Assert.assertEquals(result, expectedResult, "Test case failed: " + testCase);
        }
    }

    @Test
    public void testIsTokenBindingValidWithInvalidOAuthClientException() throws Exception {

        OAuth2AccessTokenHandler oAuth2AccessTokenHandler = new OAuth2AccessTokenHandler();

        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        AuthenticationRequest authenticationRequest = mock(AuthenticationRequest.class);
        Request request = mock(Request.class);
        TokenBinding tokenBinding = new TokenBinding("cookie", "bindingRef123", "value");

        when(authenticationContext.getAuthenticationRequest()).thenReturn(authenticationRequest);
        when(authenticationRequest.getRequest()).thenReturn(request);

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = mockStatic(OAuth2Util.class)) {

            // Mock to throw InvalidOAuthClientException
            mockedOAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(anyString()))
                    .thenThrow(new InvalidOAuthClientException("Invalid OAuth client"));

            // Invoke the private method using reflection
            Method isTokenBindingValidMethod = oAuth2AccessTokenHandler.getClass()
                    .getDeclaredMethod("isTokenBindingValid", MessageContext.class, TokenBinding.class,
                            String.class, String.class, String.class);
            isTokenBindingValidMethod.setAccessible(true);

            boolean result = (boolean) isTokenBindingValidMethod.invoke(oAuth2AccessTokenHandler,
                    authenticationContext, tokenBinding, "clientId", "accessToken", null);

            Assert.assertFalse(result, "Should return false when InvalidOAuthClientException occurs");
        }
    }

    @Test
    public void testIsTokenBindingValidWithOrganizationManagementException() throws Exception {

        OAuth2AccessTokenHandler oAuth2AccessTokenHandler = new OAuth2AccessTokenHandler();

        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        AuthenticationRequest authenticationRequest = mock(AuthenticationRequest.class);
        Request request = mock(Request.class);
        TokenBinding tokenBinding = new TokenBinding("cookie", "bindingRef123", "value");
        String tenantDomain = "org1";

        when(authenticationContext.getAuthenticationRequest()).thenReturn(authenticationRequest);
        when(authenticationRequest.getRequest()).thenReturn(request);

        try (MockedStatic<OrganizationManagementUtil> mockedOrgMgmtUtil =
                     mockStatic(OrganizationManagementUtil.class)) {

            // Mock to throw OrganizationManagementException
            mockedOrgMgmtUtil.when(() -> OrganizationManagementUtil.isOrganization(tenantDomain))
                    .thenThrow(new OrganizationManagementException("Error checking organization"));

            // Invoke the private method using reflection
            Method isTokenBindingValidMethod = oAuth2AccessTokenHandler.getClass()
                    .getDeclaredMethod("isTokenBindingValid", MessageContext.class, TokenBinding.class,
                            String.class, String.class, String.class);
            isTokenBindingValidMethod.setAccessible(true);

            boolean result = (boolean) isTokenBindingValidMethod.invoke(oAuth2AccessTokenHandler,
                    authenticationContext, tokenBinding, "clientId", "accessToken", tenantDomain);

            Assert.assertFalse(result, "Should return false when OrganizationManagementException occurs");
        }
    }
}
