/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.valve;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.ServletException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.auth.valve.util.CarbonUtils.setCarbonHome;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AParams.OAUTH_CONSUMER_KEY;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TENANT_NAME_FROM_CONTEXT;

public class OAuthAppTenantResolverValveTest {

    private static final String DUMMY_RESOURCE_OAUTH_2 = "https://localhost:9443/oauth2/test/resource";
    private static final String DUMMY_RESOURCE_OAUTH_10A = "https://localhost:9443/oauth/test/resource";
    private static final String DUMMY_RESOURCE_NON_OAUTH = "https://localhost:9443/test/resource";
    private static final String DUMMY_CLIENT_ID = "client_id";
    private static final String DUMMY_CLIENT_SECRET = "client_id";
    private static final String TENANT_DOMAIN = "test.tenant";
    private static final String DUMMY_BEARER_JWT_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                    "eyJpc3MiOiJJQU0gVGVzdCIsImlhdCI6MTc1ODYyMDQwMywiZXhwIjoxNzkwMTU2NDAzLCJhdWQiOiJ" +
                    "3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJqcm9ja2V0QGV4YW1wbGUuY29tIiwiY2xpZW50X2lkIjoidG" +
                    "VzdGNsaWVudGlkIn0.b5ihsYK2d63ma1TCQPaEDo3q67ybahk4kZUUfUq63Ew";

    @Mock
    private Valve valve;
    @Mock
    private Request request;
    @Mock
    private Response response;

    private OAuthAppTenantResolverValve oAuthAppTenantResolverValve;
    private OAuthAppDO oAuthAppDO;

    private final AtomicReference<Object> capturedTenantFromNextValve = new AtomicReference<>();

    private AutoCloseable openMocks;
    private MockedStatic<FrameworkUtils> frameworkUtilsStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilStatic;
    private MockedStatic<OAuth2Util> oAuth2UtilStatic;
    private MockedStatic<IdentityUtil> identityUtilStatic;
    private MockedStatic<IdentityConfigParser> identityConfigParserStatic;

    @BeforeMethod
    public void setUp() {

        // Ensure Carbon home is set to avoid static initialization issues in CarbonContext
        setCarbonHome();

        openMocks = MockitoAnnotations.openMocks(this);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setTenantDomain(TENANT_DOMAIN);
        user.setUserId("123456");
        user.setUserName("user1");
        oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setAppOwner(user);

        // Mock IdentityConfigParser to avoid file-based config initialization
        identityConfigParserStatic = mockStatic(IdentityConfigParser.class);
        IdentityConfigParser mockParser = mock(IdentityConfigParser.class);
        identityConfigParserStatic.when(IdentityConfigParser::getInstance).thenReturn(mockParser);
        Map<String, Object> emptyConfig = new HashMap<>();
        when(mockParser.getConfiguration()).thenReturn(emptyConfig);

        frameworkUtilsStatic = mockStatic(FrameworkUtils.class);
        frameworkUtilsStatic.when(() -> FrameworkUtils.startTenantFlow(anyString())).then(invocation -> null);

        identityTenantUtilStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(1);

        identityUtilStatic = mockStatic(IdentityUtil.class);
        identityUtilStatic.when(() -> IdentityUtil.getServerURL("/oauth", true, true))
                .thenReturn("https://localhost:9443/oauth");
        identityUtilStatic.when(() -> IdentityUtil.getServerURL("/oauth2", true, true))
                .thenReturn("https://localhost:9443/oauth2");

        oAuth2UtilStatic = mockStatic(OAuth2Util.class);

        oAuthAppTenantResolverValve = spy(new OAuthAppTenantResolverValve());
    }

    private void invokeAppTenantResolverValve() throws IOException, ServletException {

        doAnswer(invocation -> {
            // Capture the thread-local value before it's cleared in finally block.
            capturedTenantFromNextValve.set(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
            return null;
        }).when(valve).invoke(request, response);
        oAuthAppTenantResolverValve.setNext(valve);
        oAuthAppTenantResolverValve.invoke(request, response);
    }

    @AfterMethod
    public void tearDown() {
        if (frameworkUtilsStatic != null) frameworkUtilsStatic.close();
        if (identityTenantUtilStatic != null) identityTenantUtilStatic.close();
        if (oAuth2UtilStatic != null) oAuth2UtilStatic.close();
        if (identityUtilStatic != null) identityUtilStatic.close();
        if (identityConfigParserStatic != null) identityConfigParserStatic.close();
        if (openMocks != null) {
            try { openMocks.close(); } catch (Exception ignored) {}
        }
        capturedTenantFromNextValve.set(null);
        IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
    }

    @DataProvider
    public Object[][] invokeDataProvider() {

        return new Object[][]{
                // requestPath, clientIdParam, headerCredentials, expectedAppTenant, bearerToken.
                {DUMMY_RESOURCE_OAUTH_2, DUMMY_CLIENT_ID, null, TENANT_DOMAIN, null},
                {DUMMY_RESOURCE_OAUTH_10A, DUMMY_CLIENT_ID, null, TENANT_DOMAIN, null},
                {DUMMY_RESOURCE_NON_OAUTH, DUMMY_CLIENT_ID, null, null, null},
                {DUMMY_RESOURCE_OAUTH_2, null, new String[]{DUMMY_CLIENT_ID, DUMMY_CLIENT_SECRET}, TENANT_DOMAIN, null},
                {DUMMY_RESOURCE_OAUTH_2, null, new String[]{"user1", "password"}, null, null},
                {DUMMY_RESOURCE_NON_OAUTH, DUMMY_CLIENT_ID, null, null, DUMMY_BEARER_JWT_TOKEN},
        };
    }

    @Test(dataProvider = "invokeDataProvider")
    public void testInvoke(String requestPath, String clientIdParam, String[] headerCredentials,
                           String expectedAppTenant, String bearerToken) throws Exception {

        when(request.getRequestURL()).thenReturn(new StringBuffer(requestPath));
        if (requestPath.startsWith("/oauth/")) {
            when(request.getParameter(OAUTH_CONSUMER_KEY)).thenReturn(clientIdParam);
        } else {
            when(request.getParameter(CLIENT_ID)).thenReturn(clientIdParam);
        }

        oAuth2UtilStatic.when(() -> OAuth2Util.getAppInformationByClientIdOnly(DUMMY_CLIENT_ID)).thenReturn(oAuthAppDO);
        oAuth2UtilStatic.when(() -> OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(TENANT_DOMAIN);

        if (headerCredentials != null) {
            oAuth2UtilStatic.when(() -> OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(true);
            oAuth2UtilStatic.when(() -> OAuth2Util.extractCredentialsFromAuthzHeader(request)).thenReturn(headerCredentials);
        } else if (bearerToken != null) {
            oAuth2UtilStatic.when(() -> OAuth2Util.extractBearerTokenFromAuthzHeader(request)).thenReturn(bearerToken);
            oAuth2UtilStatic.when(() -> OAuth2Util.isJWT(bearerToken)).thenReturn(true);
            oAuth2UtilStatic.when(() -> OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(false);
        } else {
            oAuth2UtilStatic.when(() -> OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(false);
        }

        invokeAppTenantResolverValve();
        if (StringUtils.isNotBlank(expectedAppTenant)) {
            assertEquals(capturedTenantFromNextValve.get(), expectedAppTenant);
        } else {
            assertNull(capturedTenantFromNextValve.get());
        }
    }

    @Test
    public void testInvokeWithException() throws Exception {

        when(request.getRequestURL()).thenReturn(new StringBuffer(DUMMY_RESOURCE_OAUTH_2));
        oAuth2UtilStatic.when(() -> OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(true);
        oAuth2UtilStatic.when(() -> OAuth2Util.extractCredentialsFromAuthzHeader(request))
                .thenThrow(new OAuthClientAuthnException("error.message", "error.code"));
        invokeAppTenantResolverValve();
        assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
    }

    @Test
    public void testInvokeWithUnsetThreadLocal() throws Exception {

        when(request.getRequestURL()).thenReturn(new StringBuffer(DUMMY_RESOURCE_OAUTH_2));
        when(request.getParameter(CLIENT_ID)).thenReturn(CLIENT_ID);

        oAuth2UtilStatic.when(() -> OAuth2Util.getAppInformationByClientIdOnly(DUMMY_CLIENT_ID)).thenReturn(oAuthAppDO);
        oAuth2UtilStatic.when(() -> OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(TENANT_DOMAIN);

        invokeAppTenantResolverValve();
        // Should be cleared in finally block
        assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
    }
}
