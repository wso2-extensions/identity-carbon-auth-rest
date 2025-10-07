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

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.util.CommonTestUtils;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Tests for BasicClientAuthenticationHandler doAuthenticate.
 */
public class BasicClientAuthenticationHandlerTest {

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    @Mock
    private AuthenticationRequest mockAuthenticationRequest;

    private BasicClientAuthenticationHandler handler;

    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<OAuth2Util> mockedOAuth2Util;

    private static final String ALLOW_DISABLED_PROP =
            "OAuth.AllowDisabledApplicationCredentialsForAuthentication";

    @BeforeClass
    public void init() {

        CommonTestUtils.initPrivilegedCarbonContext();
        mockedIdentityUtil = mockStatic(IdentityUtil.class);
        mockedIdentityUtil.when(IdentityUtil::getIdentityConfigDirPath)
                .thenReturn(CarbonUtils.getCarbonConfigDirPath() + File.separator + "identity");
        mockedOAuth2Util = mockStatic(OAuth2Util.class);
    }

    @AfterClass
    public void cleanup() {

        if (mockedIdentityUtil != null) {
            mockedIdentityUtil.close();
        }
        if (mockedOAuth2Util != null) {
            mockedOAuth2Util.close();
        }
    }

    @BeforeMethod
    public void setUp() {

        mockAuthenticationContext = mock(AuthenticationContext.class);
        mockAuthenticationRequest = mock(AuthenticationRequest.class);
        handler = new BasicClientAuthenticationHandler();
        Request request = minimalRequest();
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);
        when(mockAuthenticationRequest.getRequest()).thenReturn(request);
    }

    @AfterMethod
    public void tearDown() {

        IdentityContext.destroyCurrentContext();
    }

    private void setupAuthHeaderAndTenant(String clientId, String clientSecret, String tenantDomain) {

        String basicToken = Base64.encodeBase64String((clientId + ":" + clientSecret)
                .getBytes(StandardCharsets.UTF_8));
        String header = "Basic " + basicToken;
        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(header);
        when(mockAuthenticationRequest.getRequestUri()).thenReturn("/t/" + tenantDomain + "/api");
    }

    private OAuthAppDO mockOAuthAppDO() {

        OAuthAppDO app = mock(OAuthAppDO.class);
        when(app.getApplicationName()).thenReturn("TestApp");
        when(app.getOauthConsumerKey()).thenReturn("client-123");
        return app;
    }

    @Test
    public void testDoAuthenticate_DisabledApp_Disallowed_ShouldFail() throws Exception {

        String clientId = "client-123";
        String clientSecret = "secret";
        String tenant = "tenant.com";
        setupAuthHeaderAndTenant(clientId, clientSecret, tenant);

        when(IdentityUtil.getProperty(ALLOW_DISABLED_PROP)).thenReturn("false");

        OAuthAppDO oAuthAppDO = mockOAuthAppDO();
        when(OAuth2Util.getAppInformationByClientId(clientId, tenant)).thenReturn(oAuthAppDO);
        when(OAuth2Util.authenticateClient(clientId, clientSecret, tenant)).thenReturn(true);

        // Service provider is disabled.
        ServiceProvider sp = mock(ServiceProvider.class);
        when(sp.isApplicationEnabled()).thenReturn(false);
        setupAppMgtService(sp);

        AuthenticationResult result = handler.doAuthenticate(mockAuthenticationContext);
        assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.FAILED);
    }

    @Test
    public void testDoAuthenticate_DisabledApp_Allowed_ValidCredentials_ShouldSucceed() throws Exception {

        String clientId = "client-123";
        String clientSecret = "secret";
        String tenant = "tenant.com";
        setupAuthHeaderAndTenant(clientId, clientSecret, tenant);

        when(IdentityUtil.getProperty(ALLOW_DISABLED_PROP)).thenReturn("true");

        OAuthAppDO oAuthAppDO = mockOAuthAppDO();
        when(OAuth2Util.getAppInformationByClientId(clientId, tenant)).thenReturn(oAuthAppDO);
        when(OAuth2Util.authenticateClient(clientId, clientSecret, tenant)).thenReturn(true);

        ServiceProvider sp = mock(ServiceProvider.class);
        when(sp.isApplicationEnabled()).thenReturn(false);
        setupAppMgtService(sp);

        AuthenticationResult result = handler.doAuthenticate(mockAuthenticationContext);
        assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    @Test
    public void testDoAuthenticate_DisabledApp_Allowed_InvalidCredentials_ShouldFail() throws Exception {

        String clientId = "client-123";
        String clientSecret = "wrongSecret";
        String tenant = "tenant.com";
        setupAuthHeaderAndTenant(clientId, clientSecret, tenant);

        when(IdentityUtil.getProperty(ALLOW_DISABLED_PROP)).thenReturn("true");

        OAuthAppDO oAuthAppDO = mockOAuthAppDO();
        when(OAuth2Util.getAppInformationByClientId(clientId, tenant)).thenReturn(oAuthAppDO);
        when(OAuth2Util.authenticateClient(clientId, clientSecret, tenant)).thenReturn(false);

        ServiceProvider sp = mock(ServiceProvider.class);
        when(sp.isApplicationEnabled()).thenReturn(false);
        setupAppMgtService(sp);

        AuthenticationResult result = handler.doAuthenticate(mockAuthenticationContext);
        assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.FAILED);
    }

    @Test
    public void testDoAuthenticate_NullServiceProvider_Disallowed_ShouldFail() throws Exception {

        String clientId = "client-123";
        String clientSecret = "secret";
        String tenant = "tenant.com";
        setupAuthHeaderAndTenant(clientId, clientSecret, tenant);

        when(IdentityUtil.getProperty(ALLOW_DISABLED_PROP)).thenReturn("false");

        OAuthAppDO oAuthAppDO = mockOAuthAppDO();
        when(OAuth2Util.getAppInformationByClientId(clientId, tenant)).thenReturn(oAuthAppDO);
        when(OAuth2Util.authenticateClient(clientId, clientSecret, tenant)).thenReturn(true);

        AuthenticationResult result = handler.doAuthenticate(mockAuthenticationContext);
        assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.FAILED);
    }

    @Test
    public void testDoAuthenticate_NullServiceProvider_Allowed_ValidCredentials_ShouldSucceed() throws Exception {

        String clientId = "client-123";
        String clientSecret = "secret";
        String tenant = "tenant.com";
        setupAuthHeaderAndTenant(clientId, clientSecret, tenant);

        when(IdentityUtil.getProperty(ALLOW_DISABLED_PROP)).thenReturn("true");

        OAuthAppDO oAuthAppDO = mockOAuthAppDO();
        when(OAuth2Util.getAppInformationByClientId(clientId, tenant)).thenReturn(oAuthAppDO);
        when(OAuth2Util.authenticateClient(clientId, clientSecret, tenant)).thenReturn(true);

        AuthenticationResult result = handler.doAuthenticate(mockAuthenticationContext);
        assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticate_InvalidHeader_ShouldThrow() throws Exception {

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("InvalidHeader");
        handler.doAuthenticate(mockAuthenticationContext);
    }

    private void setupAppMgtService(ServiceProvider sp) throws Exception {

        ApplicationManagementService appMgtService = mock(ApplicationManagementService.class);
        when(appMgtService.getServiceProviderByClientId(eq("client-123"), any(String.class), eq("tenant.com")))
                .thenReturn(sp);
        OAuth2ServiceComponentHolder.setApplicationMgtService(appMgtService);
    }

    private Request minimalRequest() {
        try {
            Connector connector = new Connector();
            connector.setParseBodyMethods("POST");
            Request catalina = new Request(connector);
            org.apache.coyote.Request coyote = new org.apache.coyote.Request();

            catalina.setCoyoteRequest(coyote);

            coyote.method().setString("GET");
            coyote.scheme().setString("http");
            coyote.serverName().setString("localhost");
            coyote.setServerPort(8080);
            coyote.requestURI().setString("/foo");
            coyote.getParameters().addParameter("appTenant", "tenant.com");

            return catalina;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
