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
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AParams.OAUTH_CONSUMER_KEY;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TENANT_NAME_FROM_CONTEXT;

@PrepareForTest({OAuthAppTenantResolverValve.class, OAuth2Util.class, LoggerUtils.class,
        OAuthServerConfiguration.class, IdentityUtil.class, PrivilegedCarbonContext.class, IdentityTenantUtil.class,
        FrameworkUtils.class})
@SuppressStaticInitializationFor("org.wso2.carbon.context.CarbonContext")
public class OAuthAppTenantResolverValveTest extends PowerMockTestCase {

    private static final String DUMMY_RESOURCE_OAUTH_2 = "https://localhost:9443/oauth2/test/resource";
    private static final String DUMMY_RESOURCE_OAUTH_10A = "https://localhost:9443/oauth/test/resource";
    private static final String DUMMY_RESOURCE_NON_OAUTH = "https://localhost:9443/test/resource";
    private static final String DUMMY_CLIENT_ID = "client_id";
    private static final String DUMMY_CLIENT_SECRET = "client_id";
    private static final String TENANT_DOMAIN = "test.tenant";

    @Mock
    private Valve valve;
    @Mock
    private Request request;
    @Mock
    private Response response;

    private OAuthAppTenantResolverValve oAuthAppTenantResolverValve;
    private OAuthAppDO oAuthAppDO;

    private ThreadLocal<Map<String, Object>> threadLocalProperties = new ThreadLocal<Map<String, Object>>() {
        protected Map<String, Object> initialValue() {
            return new HashMap();
        }
    };

    @BeforeMethod
    public void setUp() throws Exception {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setTenantDomain(TENANT_DOMAIN);
        user.setUserId("123456");
        user.setUserName("user1");
        oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setAppOwner(user);

        mockStatic(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(mock(PrivilegedCarbonContext.class));

        mockStatic(FrameworkUtils.class);
        PowerMockito.doNothing()
                .when(FrameworkUtils.class, "startTenantFlow", anyString());

        RealmService realmService = mock(RealmService.class);
        TenantManager tenantManager = mock(TenantManager.class);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(TENANT_DOMAIN)).thenReturn(1);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(1);

        OAuthServerConfiguration oAuthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfigurationMock);

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(false);
        mockStatic(OAuth2Util.class);

        mockStatic(IdentityUtil.class);
        threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
        Whitebox.setInternalState(IdentityUtil.class, "threadLocalProperties", threadLocalProperties);
        when(IdentityUtil.getServerURL("/oauth", true, true)).thenReturn("https://localhost:9443/oauth");
        when(IdentityUtil.getServerURL("/oauth2", true, true)).thenReturn("https://localhost:9443/oauth2");

        oAuthAppTenantResolverValve = spy(new OAuthAppTenantResolverValve());
    }

    private void invokeAppTenantResolverValve() throws IOException, ServletException {

        doNothing().when(valve).invoke(request, response);
        oAuthAppTenantResolverValve.setNext(valve);
        oAuthAppTenantResolverValve.invoke(request, response);
    }

    @DataProvider
    public Object[][] invokeDataProvider() {

        return new Object[][]{
                // requestPath, clientIdParam, headerCredentials, expectedAppTenant.
                {DUMMY_RESOURCE_OAUTH_2, DUMMY_CLIENT_ID, null, TENANT_DOMAIN},
                {DUMMY_RESOURCE_OAUTH_10A, DUMMY_CLIENT_ID, null, TENANT_DOMAIN},
                {DUMMY_RESOURCE_NON_OAUTH, DUMMY_CLIENT_ID, null, null},
                {DUMMY_RESOURCE_OAUTH_2, null, new String[]{DUMMY_CLIENT_ID, DUMMY_CLIENT_SECRET}, TENANT_DOMAIN},
                {DUMMY_RESOURCE_OAUTH_2, null, new String[]{"user1", "password"}, null},
                {DUMMY_RESOURCE_OAUTH_2, null, null, null}
        };
    }

    @Test(dataProvider = "invokeDataProvider")
    public void testInvoke(String requestPath, String clientIdParam, String[] headerCredentials,
                           String expectedAppTenant) throws Exception {

        // Suppress the execution of cleaning methods inorder to assert the correct behaviour.
        PowerMockito.suppress(PowerMockito.method(
                OAuthAppTenantResolverValve.class, "unsetThreadLocalContextTenantName"));

        when(request.getRequestURL()).thenReturn(new StringBuffer(requestPath));
        if (requestPath.startsWith("/oauth/")) {
            when(request.getParameter(OAUTH_CONSUMER_KEY)).thenReturn(clientIdParam);
        } else {
            when(request.getParameter(CLIENT_ID)).thenReturn(clientIdParam);
        }

        when(OAuth2Util.getAppInformationByClientIdOnly(DUMMY_CLIENT_ID)).thenReturn(oAuthAppDO);
        when(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(TENANT_DOMAIN);
        if (headerCredentials != null) {
            when(OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(true);
            when(OAuth2Util.extractCredentialsFromAuthzHeader(request)).thenReturn(headerCredentials);
        } else {
            when(OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(false);
        }

        invokeAppTenantResolverValve();
        if (StringUtils.isNotBlank(expectedAppTenant)) {
            assertEquals(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT), expectedAppTenant);
        } else {
            assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
        }
    }

    @Test
    public void testInvokeWithException() throws Exception {

        // Suppress the execution of cleaning methods inorder to assert the correct behaviour.
        PowerMockito.suppress(PowerMockito.method(
                OAuthAppTenantResolverValve.class, "unsetThreadLocalContextTenantName"));

        when(request.getRequestURL()).thenReturn(new StringBuffer(DUMMY_RESOURCE_OAUTH_2));
        when(OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(true);
        when(OAuth2Util.extractCredentialsFromAuthzHeader(request)).thenThrow(
                new OAuthClientAuthnException("error.message", "error.code"));
        invokeAppTenantResolverValve();
        assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
    }

    @Test
    public void testInvokeWithUnsetThreadLocal() throws Exception {

        when(request.getRequestURL()).thenReturn(new StringBuffer(DUMMY_RESOURCE_OAUTH_2));
        when(request.getParameter(CLIENT_ID)).thenReturn(CLIENT_ID);

        when(OAuth2Util.getAppInformationByClientIdOnly(DUMMY_CLIENT_ID)).thenReturn(oAuthAppDO);
        when(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(TENANT_DOMAIN);

        invokeAppTenantResolverValve();
        assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
    }
}
