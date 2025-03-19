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

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.CommonTestUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Test class for BasicAuthenticationHandler.
 */
public class BasicAuthenticationHandlerTest {

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    @Mock
    private AuthenticationRequest mockAuthenticationRequest;

    @Mock
    private RealmService mockRealmService;

    @Mock
    private UserRealm mockUserRealm;

    @Mock
    private AbstractUserStoreManager mockUserStoreManager;

    @Mock
    private OrganizationManager mockOrganizationManager;

    @Mock
    private AuthenticationServiceHolder mockAuthenticationServiceHolder;

    private BasicAuthenticationHandler basicAuthenticationHandler;
    private MockedStatic<AuthConfigurationUtil> mockedAuthConfigurationUtil;
    private MockedStatic<MultitenantUtils> mockedMultitenantUtils;
    private MockedStatic<UserCoreUtil> mockedUserCoreUtil;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private MockedStatic<AuthenticationServiceHolder> mockedAuthenticationServiceHolder;

    private static final int TEST_TENANT_ID = 1;
    private static final String TEST_TENANT_DOMAIN = "test.com";

    @BeforeClass
    public void init() {

        CommonTestUtils.initPrivilegedCarbonContext();
        mockedAuthConfigurationUtil = mockStatic(AuthConfigurationUtil.class);
        mockedMultitenantUtils = mockStatic(MultitenantUtils.class);
        mockedUserCoreUtil = mockStatic(UserCoreUtil.class);
        mockedIdentityUtil = mockStatic(IdentityUtil.class);
        mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        mockedAuthenticationServiceHolder = mockStatic(AuthenticationServiceHolder.class);
    }

    @AfterClass
    public void close() {

        mockedAuthConfigurationUtil.close();
        mockedMultitenantUtils.close();
        mockedUserCoreUtil.close();
        mockedIdentityUtil.close();
        mockedIdentityTenantUtil.close();
        mockedAuthenticationServiceHolder.close();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);

        basicAuthenticationHandler = new BasicAuthenticationHandler();

        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);
        when(AuthenticationServiceHolder.getInstance()).thenReturn(mockAuthenticationServiceHolder);
        when(mockAuthenticationServiceHolder.getRealmService()).thenReturn(mockRealmService);
        when(mockAuthenticationServiceHolder.getOrganizationManager()).thenReturn(mockOrganizationManager);

        // Instead of stubbing the field getter, set the ThreadLocal directly.
        Map<String, Object> threadLocalMap = new HashMap<>();
        IdentityUtil.threadLocalProperties.set(threadLocalMap);
    }

    @AfterMethod
    public void tearDown() {

        IdentityContext.destroyCurrentContext();
    }

    @Test
    public void testGetName() {

        assertEquals(basicAuthenticationHandler.getName(), "BasicAuthentication");
    }

    @Test
    public void testGetPriority() {

        MessageContext mockMessageContext = mock(MessageContext.class);
        assertEquals(basicAuthenticationHandler.getPriority(mockMessageContext), 100);
    }

    @Test
    public void testCanHandle() {

        MessageContext mockMessageContext = mock(MessageContext.class);
        mockedAuthConfigurationUtil.when(() ->
                        AuthConfigurationUtil.isAuthHeaderMatch(mockMessageContext, "Basic"))
                .thenReturn(true);
        assertTrue(basicAuthenticationHandler.canHandle(mockMessageContext));

        mockedAuthConfigurationUtil.when(() ->
                        AuthConfigurationUtil.isAuthHeaderMatch(mockMessageContext, "Basic"))
                .thenReturn(false);
        assertFalse(basicAuthenticationHandler.canHandle(mockMessageContext));
    }

    @Test
    public void testDoAuthenticateSuccess() throws Exception {

        String username = "alice@example.com";
        String password = "temp123";
        String usernameWithTenantDomain = username + "@" + TEST_TENANT_DOMAIN;
        String apiResource = "/api/resource";
        String authHeader = "Basic " +
                Base64.encodeBase64String((usernameWithTenantDomain + ":" + password).getBytes(StandardCharsets.UTF_8));

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn(apiResource);

        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(usernameWithTenantDomain))
                .thenReturn(TEST_TENANT_ID);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantDomain(usernameWithTenantDomain))
                .thenReturn(TEST_TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(usernameWithTenantDomain)).thenReturn(username);
        when(MultitenantUtils.isEmailUserName()).thenReturn(false);

        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        org.wso2.carbon.user.core.common.AuthenticationResult mockAuthResult =
                mock(org.wso2.carbon.user.core.common.AuthenticationResult.class);
        when(mockAuthResult.getAuthenticationStatus())
                .thenReturn(org.wso2.carbon.user.core.common.AuthenticationResult.AuthenticationStatus.SUCCESS);

        User mockUser = mock(User.class);
        when(mockUser.getUserID()).thenReturn("user-123");
        when(mockUser.getUsername()).thenReturn(username);
        Optional<User> optionalUser = Optional.of(mockUser);
        when(mockAuthResult.getAuthenticatedUser()).thenReturn(optionalUser);

        when(mockUserStoreManager.authenticateWithID(
                eq(UserCoreClaimConstants.USERNAME_CLAIM_URI),
                eq(username),
                eq(password),
                any(String.class)))
                .thenReturn(mockAuthResult);

        mockedUserCoreUtil.when(() -> UserCoreUtil.getDomainFromThreadLocal()).thenReturn("PRIMARY");
        AuthenticationResult result = basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
        Assert.assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticateWithoutTenantDomainInUsername() throws Exception {

        String username = "alice@example.com";
        String password = "temp123";
        String apiResource = "/api/resource";
        String authHeader = "Basic " +
                Base64.encodeBase64String((username + ":" + password).getBytes(StandardCharsets.UTF_8));

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn(apiResource);

        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(username))
                .thenThrow(IdentityRuntimeException.error("Invalid tenant domain"));

        basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
    }

    @Test(expectedExceptions = IdentityRuntimeException.class)
    public void testDoAuthenticateIdentityRuntimeException() throws Exception {

        String username = "alice@example.com";
        String password = "temp123";
        String apiResource = "/api/resource";
        String authHeader = "Basic " +
                Base64.encodeBase64String((username + ":" + password).getBytes(StandardCharsets.UTF_8));

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn(apiResource);

        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(username))
                .thenThrow(IdentityRuntimeException.error("Other error"));

        basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticateInvalidHeaderFormat() throws Exception {

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("InvalidHeader");
        basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticateInvalidCredentialsFormat() throws Exception {

        String authHeader = "Basic " + Base64.encodeBase64String("alice".getBytes(StandardCharsets.UTF_8));
        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
    }
}
