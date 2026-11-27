/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.CommonTestUtils;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.compatibility.settings.core.CompatibilitySettingsManagerImpl;
import org.wso2.carbon.identity.compatibility.settings.core.exception.CompatibilitySettingException;
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySetting;
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySettingGroup;
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
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.apache.catalina.connector.Request;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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

    @Mock
    private CompatibilitySettingsManagerImpl mockCompatibilitySettingsManager;

    @Mock
    private Request mockRequest;

    private BasicAuthenticationHandler basicAuthenticationHandler;
    private MockedStatic<AuthConfigurationUtil> mockedAuthConfigurationUtil;
    private MockedStatic<MultitenantUtils> mockedMultitenantUtils;
    private MockedStatic<UserCoreUtil> mockedUserCoreUtil;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private MockedStatic<AuthenticationServiceHolder> mockedAuthenticationServiceHolder;

    private static final int TEST_TENANT_ID = 1;
    private static final String TEST_TENANT_DOMAIN = "test.com";
    private static final String TEST_USERNAME = "alice@example.com";
    private static final String SCIM2 = "scim2";

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
        when(mockAuthenticationServiceHolder.getCompatibilitySettingsManager()).thenReturn(mockCompatibilitySettingsManager);

        // Instead of stubbing the field getter, set the ThreadLocal directly.
        Map<String, Object> threadLocalMap = new HashMap<>();
        IdentityUtil.threadLocalProperties.set(threadLocalMap);
    }

    @AfterMethod
    public void tearDown() {

        IdentityContext.destroyCurrentContext();
        mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                Constants.BASIC_AUTH_FALLBACK_TO_REQUEST_TENANT_CONFIG)).thenReturn(null);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(false);
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

    @DataProvider(name = "usernamesWithOtherTenantDomain")
    public Object[][] usernamesWithOtherTenantDomain() {

        return new Object[][]{
                // Email username whose domain is not a tenant.
                {"user@example.org", "example.org"},
                // Email username whose domain is an existing tenant (e.g. a sub-organization handle).
                {"user@abc.com", "abc.com"}
        };
    }

    @Test(dataProvider = "usernamesWithOtherTenantDomain")
    public void testDoAuthenticateUsesRequestTenantWhenUsernameTenantDiffers(String username,
                                                                             String tenantDomainFromUsername)
            throws Exception {

        String password = "temp123";
        String superTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        setUpBasicAuthRequest(username, password);
        enableFallbackToRequestTenant(superTenantDomain);

        mockedIdentityTenantUtil.clearInvocations();
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantDomain(username))
                .thenReturn(tenantDomainFromUsername);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(superTenantDomain))
                .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        stubSuccessfulAuthentication(username, password);

        AuthenticationResult result = basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);

        Assert.assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
        verify(mockRealmService).getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID);
        verify(mockAuthenticationContext, atLeastOnce()).setUser(
                argThat(user -> username.equals(user.getUserName()) &&
                        superTenantDomain.equals(user.getTenantDomain())));
        mockedIdentityTenantUtil.verify(() -> IdentityTenantUtil.getTenantIdOfUser(username), never());
    }

    @Test
    public void testDoAuthenticateKeepsUsernameTenantWhenItMatchesRequestTenant() throws Exception {

        String usernameWithTenantDomain = TEST_USERNAME + "@" + TEST_TENANT_DOMAIN;
        String password = "temp123";
        setUpBasicAuthRequest(usernameWithTenantDomain, password);
        enableFallbackToRequestTenant(TEST_TENANT_DOMAIN);

        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantDomain(usernameWithTenantDomain))
                .thenReturn(TEST_TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(usernameWithTenantDomain)).thenReturn(TEST_USERNAME);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(usernameWithTenantDomain))
                .thenReturn(TEST_TENANT_ID);
        stubSuccessfulAuthentication(TEST_USERNAME, password);

        AuthenticationResult result = basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);

        Assert.assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
        verify(mockRealmService).getTenantUserRealm(TEST_TENANT_ID);
    }

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticateDoesNotFallBackWhenConfigDisabled() throws Exception {

        String username = "user@example.org";
        setUpBasicAuthRequest(username, "temp123");
        mockedIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(true);

        mockedIdentityTenantUtil.clearInvocations();
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(username))
                .thenThrow(IdentityRuntimeException.error("Invalid tenant domain example.org"));
        try {
            basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
        } finally {
            mockedIdentityTenantUtil.verify(IdentityTenantUtil::resolveTenantDomain, never());
        }
    }

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticateDoesNotFallBackWithoutTenantQualifiedUrls() throws Exception {

        String username = "user@example.org";
        setUpBasicAuthRequest(username, "temp123");
        enableFallbackToRequestTenant(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(false);

        mockedIdentityTenantUtil.clearInvocations();
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(username))
                .thenThrow(IdentityRuntimeException.error("Invalid tenant domain example.org"));
        try {
            basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
        } finally {
            mockedIdentityTenantUtil.verify(IdentityTenantUtil::resolveTenantDomain, never());
        }
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

    @Test(expectedExceptions = AuthenticationFailException.class,
            expectedExceptionsMessageRegExp = "Basic authentication is not allowed for scim2/Me endpoint")
    public void testDoAuthenticateScim2MeEndpointWithBasicAuthDisabled() throws Exception {

        String username = "alice@example.com";
        String password = "temp123";
        String usernameWithTenantDomain = username + "@" + TEST_TENANT_DOMAIN;
        String apiResource = "/t/" + TEST_TENANT_DOMAIN + "/scim2/me";
        String authHeader = "Basic " +
                Base64.encodeBase64String((usernameWithTenantDomain + ":" + password).getBytes(StandardCharsets.UTF_8));

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn(apiResource);
        when(mockAuthenticationRequest.getRequest()).thenReturn(mockRequest);
        when(mockRequest.getRequestURI()).thenReturn(apiResource);

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

        mockedUserCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn("PRIMARY");

        // Setup compatibility settings to disable basic auth for scim2/me.
        CompatibilitySetting mockCompatibilitySetting = mock(CompatibilitySetting.class);
        CompatibilitySettingGroup mockSettingGroup = mock(CompatibilitySettingGroup.class);
        Map<String, CompatibilitySettingGroup> settingsMap = new HashMap<>();
        settingsMap.put(SCIM2, mockSettingGroup);

        when(mockCompatibilitySettingsManager.getCompatibilitySettingsByGroupAndSetting(
                eq(TEST_TENANT_DOMAIN), eq(SCIM2), eq("disableBasicAuthForMeEndpoint")))
                .thenReturn(mockCompatibilitySetting);
        when(mockCompatibilitySetting.getCompatibilitySettings()).thenReturn(settingsMap);
        when(mockSettingGroup.getSettingValue("disableBasicAuthForMeEndpoint")).thenReturn("true");

        basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
    }

    @Test
    public void testDoAuthenticateScim2MeEndpointWithBasicAuthEnabled() throws Exception {

        String username = "alice@example.com";
        String password = "temp123";
        String usernameWithTenantDomain = username + "@" + TEST_TENANT_DOMAIN;
        String apiResource = "/t/" + TEST_TENANT_DOMAIN + "/scim2/me";
        String authHeader = "Basic " +
                Base64.encodeBase64String((usernameWithTenantDomain + ":" + password).getBytes(StandardCharsets.UTF_8));

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn(apiResource);
        when(mockAuthenticationRequest.getRequest()).thenReturn(mockRequest);
        when(mockRequest.getRequestURI()).thenReturn(apiResource);

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

        mockedUserCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn("PRIMARY");

        // Setup compatibility settings to allow basic auth for scim2/me.
        CompatibilitySetting mockCompatibilitySetting = mock(CompatibilitySetting.class);
        CompatibilitySettingGroup mockSettingGroup = mock(CompatibilitySettingGroup.class);
        Map<String, CompatibilitySettingGroup> settingsMap = new HashMap<>();
        settingsMap.put(SCIM2, mockSettingGroup);

        when(mockCompatibilitySettingsManager.getCompatibilitySettingsByGroupAndSetting(
                eq(TEST_TENANT_DOMAIN), eq(SCIM2), eq("disableBasicAuthForMeEndpoint")))
                .thenReturn(mockCompatibilitySetting);
        when(mockCompatibilitySetting.getCompatibilitySettings()).thenReturn(settingsMap);
        when(mockSettingGroup.getSettingValue("disableBasicAuthForMeEndpoint")).thenReturn("false");

        AuthenticationResult result = basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
        Assert.assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    @Test
    public void testDoAuthenticateScim2MeEndpointWithCompatibilitySettingException() throws Exception {

        String username = "alice@example.com";
        String password = "temp123";
        String usernameWithTenantDomain = username + "@" + TEST_TENANT_DOMAIN;
        String apiResource = "/t/" + TEST_TENANT_DOMAIN + "/scim2/me";
        String authHeader = "Basic " +
                Base64.encodeBase64String((usernameWithTenantDomain + ":" + password).getBytes(StandardCharsets.UTF_8));

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn(apiResource);
        when(mockAuthenticationRequest.getRequest()).thenReturn(mockRequest);
        when(mockRequest.getRequestURI()).thenReturn(apiResource);

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

        mockedUserCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn("PRIMARY");

        // Setup compatibility settings to throw exception.
        when(mockCompatibilitySettingsManager.getCompatibilitySettingsByGroupAndSetting(
                eq(TEST_TENANT_DOMAIN), eq(SCIM2), eq("disableBasicAuthForMeEndpoint")))
                .thenThrow(new CompatibilitySettingException("Setting not found"));

        // Should still authenticate successfully when CompatibilitySettingException is thrown.
        AuthenticationResult result = basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
        Assert.assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    @Test
    public void testDoAuthenticateNonScim2MeEndpoint() throws Exception {

        String username = "alice@example.com";
        String password = "temp123";
        String usernameWithTenantDomain = username + "@" + TEST_TENANT_DOMAIN;
        String apiResource = "/api/resource";
        String authHeader = "Basic " +
                Base64.encodeBase64String((usernameWithTenantDomain + ":" + password).getBytes(StandardCharsets.UTF_8));

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn(apiResource);
        when(mockAuthenticationRequest.getRequest()).thenReturn(mockRequest);
        when(mockRequest.getRequestURI()).thenReturn(apiResource);

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

        mockedUserCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn("PRIMARY");

        // Should not call compatibility settings service for non-scim2/me endpoint.
        AuthenticationResult result = basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
        Assert.assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    private void enableFallbackToRequestTenant(String requestTenantDomain) {

        mockedIdentityUtil.when(() -> IdentityUtil.getProperty(Constants.BASIC_AUTH_FALLBACK_TO_REQUEST_TENANT_CONFIG))
                .thenReturn("true");
        mockedIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(true);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::resolveTenantDomain).thenReturn(requestTenantDomain);
    }

    private void setUpBasicAuthRequest(String username, String password) {

        String authHeader = "Basic " +
                Base64.encodeBase64String((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn("/scim2/Me");
    }

    private void stubSuccessfulAuthentication(String tenantAwareUsername, String password) throws Exception {

        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        org.wso2.carbon.user.core.common.AuthenticationResult mockAuthResult =
                mock(org.wso2.carbon.user.core.common.AuthenticationResult.class);
        when(mockAuthResult.getAuthenticationStatus())
                .thenReturn(org.wso2.carbon.user.core.common.AuthenticationResult.AuthenticationStatus.SUCCESS);
        User mockUser = mock(User.class);
        when(mockUser.getUserID()).thenReturn("user-123");
        when(mockUser.getUsername()).thenReturn(tenantAwareUsername);
        when(mockAuthResult.getAuthenticatedUser()).thenReturn(Optional.of(mockUser));

        when(mockUserStoreManager.authenticateWithID(eq(UserCoreClaimConstants.USERNAME_CLAIM_URI),
                eq(tenantAwareUsername), eq(password), any(String.class))).thenReturn(mockAuthResult);
        mockedUserCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn("PRIMARY");
    }
}
