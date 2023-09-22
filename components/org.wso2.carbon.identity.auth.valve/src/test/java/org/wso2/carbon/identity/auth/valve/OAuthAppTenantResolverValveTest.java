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
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import javax.servlet.ServletException;

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

@PrepareForTest({OAuthAppTenantResolverValve.class, IdentityTenantUtil.class, OAuth2Util.class,
        LoggerUtils.class, OAuthServerConfiguration.class})
public class OAuthAppTenantResolverValveTest extends PowerMockTestCase {

    private static final String DUMMY_RESOURCE_OAUTH_2 = "/oauth2/test/resource";
    private static final String DUMMY_RESOURCE_OAUTH_10A = "/oauth/test/resource";
    private static final String DUMMY_RESOURCE_NON_OAUTH = "/test/resource";
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

    @BeforeMethod
    public void setUp() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(false);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setTenantDomain(TENANT_DOMAIN);
        user.setUserId("123456");
        user.setUserName("user1");
        oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setAppOwner(user);

        OAuthServerConfiguration oAuthServerConfigurationMock = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfigurationMock);

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(false);
        mockStatic(OAuth2Util.class);

        oAuthAppTenantResolverValve = spy(new OAuthAppTenantResolverValve());
        IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
    }

    private void invokeAppTenantResolverValve() throws IOException, ServletException {

        doNothing().when(valve).invoke(request, response);
        oAuthAppTenantResolverValve.setNext(valve);
        oAuthAppTenantResolverValve.invoke(request, response);
    }

    @Test
    public void testInvokeWhenTenantQualifiedUrlsEnabled() throws Exception {

        // Suppress the execution of cleaning methods inorder to assert the correct behaviour.
        PowerMockito.suppress(PowerMockito.method(
                OAuthAppTenantResolverValve.class, "unsetThreadLocalContextTenantName"));

        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        invokeAppTenantResolverValve();
        Assert.assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
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

        when(request.getRequestURI()).thenReturn(requestPath);
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
    public void testInvokeWithException(Exception expectedException) throws Exception {

        // Suppress the execution of cleaning methods inorder to assert the correct behaviour.
        PowerMockito.suppress(PowerMockito.method(
                OAuthAppTenantResolverValve.class, "unsetThreadLocalContextTenantName"));

        when(OAuth2Util.isBasicAuthorizationHeaderExists(request)).thenReturn(true);
        when(OAuth2Util.extractCredentialsFromAuthzHeader(request)).thenThrow(
                new OAuthClientAuthnException("error.message", "error.code"));
        invokeAppTenantResolverValve();
        assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
    }

    @Test
    public void testInvokeWithUnsetThreadLocal() throws Exception {

        when(request.getRequestURI()).thenReturn(DUMMY_RESOURCE_OAUTH_2);
        when(request.getParameter(CLIENT_ID)).thenReturn(CLIENT_ID);

        when(OAuth2Util.getAppInformationByClientIdOnly(DUMMY_CLIENT_ID)).thenReturn(oAuthAppDO);
        when(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)).thenReturn(TENANT_DOMAIN);

        invokeAppTenantResolverValve();
        assertNull(IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT));
    }
}
