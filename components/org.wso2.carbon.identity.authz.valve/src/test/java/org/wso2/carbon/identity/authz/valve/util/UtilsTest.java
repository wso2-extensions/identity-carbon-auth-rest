/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.authz.valve.util;

import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.orgdiscovery.OrganizationDiscoveryHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryInput;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryResult;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.authz.valve.internal.AuthorizationValveServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.wso2.carbon.identity.auth.service.util.Constants.SERVICE_PROVIDER_UUID;

/**
 * Unit test class for {@link Utils}.
 */
public class UtilsTest {

    private static final String URL_TENANT_DOMAIN = "tenantA";
    private static final String URL_ORG_ID = "orgId1";
    private static final String USER_TENANT_DOMAIN = "tenantB";
    private static final String ACCESSING_ORG_ID = "orgId2";
    private static final String OAUTH_APP_TENANT = "appTenant";
    private static final String ACCESSING_TENANT = "accessingTenant";
    private static final String SP_UUID = "sp-uuid-123";
    private static final String REQUEST_URI = "/t/" + URL_TENANT_DOMAIN + "/scim2/me";

    @Mock
    private AuthenticationContext authenticationContext;
    @Mock
    private AuthenticationRequest authenticationRequest;
    @Mock
    private AuthenticatedUser user;
    @Mock
    private OAuthAppDO oAuthAppDO;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private OrganizationManager organizationManager;
    @Mock
    private OrganizationDiscoveryHandler organizationDiscoveryHandler;
    @Mock
    private OrganizationDiscoveryResult organizationDiscoveryResult;
    @Mock
    private AuthorizationValveServiceHolder serviceHolder;

    private AutoCloseable closeable;
    private MockedStatic<Utils> mockedUtils;
    private MockedStatic<IdentityTenantUtil> mockedTenantUtil;
    private MockedStatic<AuthConfigurationUtil> mockedAuthConfig;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<OAuthServerConfiguration> mockedOAuthServerConfig;
    private MockedStatic<OAuth2Util> mockedOAuth2Util;
    private MockedStatic<AuthorizationValveServiceHolder> mockedHolder;

    @BeforeMethod
    public void setUp() throws OrganizationManagementException {

        closeable = MockitoAnnotations.openMocks(this);

        mockedUtils = mockStatic(Utils.class, withSettings().defaultAnswer(Answers.CALLS_REAL_METHODS));
        mockedTenantUtil = mockStatic(IdentityTenantUtil.class);
        mockedAuthConfig = mockStatic(AuthConfigurationUtil.class);
        mockedIdentityUtil = mockStatic(IdentityUtil.class);
        // OAuthServerConfiguration must be mocked and its getInstance() stubbed before OAuth2Util
        // is instrumented, so that OAuth2Util's static initializer receives a mock instance
        // instead of triggering real Carbon config loading.
        mockedOAuthServerConfig = mockStatic(OAuthServerConfiguration.class);
        mockedOAuthServerConfig.when(OAuthServerConfiguration::getInstance).thenReturn(oAuthServerConfiguration);
        mockedOAuth2Util = mockStatic(OAuth2Util.class);
        mockedHolder = mockStatic(AuthorizationValveServiceHolder.class);

        mockedUtils.when(() -> Utils.getTenantDomainFromURLMapping(any())).thenReturn(URL_TENANT_DOMAIN);
        mockedUtils.when(() -> Utils.getOrganizationIdFromURLMapping(any())).thenReturn(URL_ORG_ID);
        mockedTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(true);
        mockedAuthConfig.when(
                () -> AuthConfigurationUtil.getResourceResidentTenantForTenantPerspective(anyString()))
                .thenReturn(null);
        mockedOAuth2Util.when(() -> OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(OAUTH_APP_TENANT);
        mockedHolder.when(AuthorizationValveServiceHolder::getInstance).thenReturn(serviceHolder);

        when(authenticationContext.getUser()).thenReturn(user);
        when(authenticationContext.getAuthenticationRequest()).thenReturn(authenticationRequest);
        when(authenticationRequest.getRequestUri()).thenReturn(REQUEST_URI);
        when(user.getTenantDomain()).thenReturn(USER_TENANT_DOMAIN);
        when(user.getAccessingOrganization()).thenReturn(ACCESSING_ORG_ID);
        when(authenticationContext.getParameter(Constants.AUTH_CONTEXT_OAUTH_APP_PROPERTY)).thenReturn(oAuthAppDO);
        when(serviceHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(serviceHolder.getOrganizationDiscoveryHandler()).thenReturn(organizationDiscoveryHandler);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        mockedHolder.close();
        mockedOAuth2Util.close();
        mockedOAuthServerConfig.close();
        mockedIdentityUtil.close();
        mockedAuthConfig.close();
        mockedTenantUtil.close();
        mockedUtils.close();
        closeable.close();
    }

    @Test
    public void testIsUserBelongsToRequestedTenantWhenAccessingTenantMatchesOAuthAppTenant()
            throws OrganizationManagementException {

        when(organizationManager.resolveTenantDomain(ACCESSING_ORG_ID)).thenReturn(OAUTH_APP_TENANT);

        Assert.assertTrue(Utils.isUserBelongsToRequestedTenant(authenticationContext, null));
    }

    @Test
    public void testIsUserBelongsToRequestedTenantWhenServiceProviderUUIDMissing()
            throws OrganizationManagementException {

        when(organizationManager.resolveTenantDomain(ACCESSING_ORG_ID)).thenReturn(ACCESSING_TENANT);
        when(authenticationContext.getParameter(SERVICE_PROVIDER_UUID)).thenReturn(null);

        Assert.assertFalse(Utils.isUserBelongsToRequestedTenant(authenticationContext, null));
    }

    @Test
    public void testIsUserBelongsToRequestedTenantWhenServiceProviderUUIDEmpty()
            throws OrganizationManagementException {

        when(organizationManager.resolveTenantDomain(ACCESSING_ORG_ID)).thenReturn(ACCESSING_TENANT);
        when(authenticationContext.getParameter(SERVICE_PROVIDER_UUID)).thenReturn("");

        Assert.assertFalse(Utils.isUserBelongsToRequestedTenant(authenticationContext, null));
    }

    @Test
    public void testIsUserBelongsToRequestedTenantWhenOrganizationDiscoverySucceeds()
            throws OrganizationManagementException, FrameworkException {

        when(organizationManager.resolveTenantDomain(ACCESSING_ORG_ID)).thenReturn(ACCESSING_TENANT);
        when(authenticationContext.getParameter(SERVICE_PROVIDER_UUID)).thenReturn(SP_UUID);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(true);
        when(organizationDiscoveryHandler.discoverOrganization(
                any(OrganizationDiscoveryInput.class), anyString(), anyString()))
                .thenReturn(organizationDiscoveryResult);

        Assert.assertTrue(Utils.isUserBelongsToRequestedTenant(authenticationContext, null));
    }

    @Test
    public void testIsUserBelongsToRequestedTenantWhenOrganizationDiscoveryFails()
            throws OrganizationManagementException, FrameworkException {

        when(organizationManager.resolveTenantDomain(ACCESSING_ORG_ID)).thenReturn(ACCESSING_TENANT);
        when(authenticationContext.getParameter(SERVICE_PROVIDER_UUID)).thenReturn(SP_UUID);
        when(organizationDiscoveryResult.isSuccessful()).thenReturn(false);
        when(organizationDiscoveryHandler.discoverOrganization(
                any(OrganizationDiscoveryInput.class), anyString(), anyString()))
                .thenReturn(organizationDiscoveryResult);

        Assert.assertFalse(Utils.isUserBelongsToRequestedTenant(authenticationContext, null));
    }

    @Test
    public void testIsUserBelongsToRequestedTenantWhenOrganizationDiscoveryThrowsFrameworkException()
            throws OrganizationManagementException, FrameworkException {

        when(organizationManager.resolveTenantDomain(ACCESSING_ORG_ID)).thenReturn(ACCESSING_TENANT);
        when(authenticationContext.getParameter(SERVICE_PROVIDER_UUID)).thenReturn(SP_UUID);
        when(organizationDiscoveryHandler.discoverOrganization(
                any(OrganizationDiscoveryInput.class), anyString(), anyString()))
                .thenThrow(new FrameworkException("Organization discovery error"));

        Assert.assertFalse(Utils.isUserBelongsToRequestedTenant(authenticationContext, null));
    }
}
