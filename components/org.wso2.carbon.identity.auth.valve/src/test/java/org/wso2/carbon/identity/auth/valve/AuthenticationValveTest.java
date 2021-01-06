/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.auth.valve;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.collections.iterators.IteratorEnumeration;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.slf4j.MDC;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.auth.valve.util.AuthHandlerManager;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;
import static org.wso2.carbon.identity.auth.valve.util.CarbonUtils.mockCarbonContextForTenant;
import static org.wso2.carbon.identity.auth.valve.util.CarbonUtils.mockIdentityTenantUtility;
import static org.wso2.carbon.identity.auth.valve.util.CarbonUtils.mockRealmService;
import static org.wso2.carbon.identity.auth.valve.util.CarbonUtils.setCarbonHome;

@PrepareForTest({AuthHandlerManager.class, AuthenticationManager.class, IdentityConfigParser.class,
        IdentityTenantUtil.class, PrivilegedCarbonContext.class})
public class AuthenticationValveTest extends PowerMockTestCase {

    private static final String DUMMY_RESOURCE = "/test/resource";
    private static final String HTTP_METHOD_POST = "POST";

    private static final String AUTH_CONTEXT = "auth-context";
    private static final String USER_AGENT = "User-Agent";
    private final String CONFIG_CONTEXTUAL_PARAM = "LoggableContextualParams.contextual_param";
    private final String CONFIG_LOG_PARAM_USER_AGENT = "user_agent";
    private final String CONFIG_LOG_PARAM_REMOTE_ADDRESS = "remote_address";

    @Mock
    private ResourceConfig securedResourceConfig;
    @Mock
    private Request request;
    @Mock
    private Response response;
    @Mock
    private Valve valve;
    @Mock
    private AuthHandlerManager authHandlerManager;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private IdentityConfigParser mockConfigParser;

    private AuthenticationValve authenticationValve;

    @DataProvider
    public Object[][] getExceptionTypeData() {

        return new Object[][]{
                {new AuthClientException("Test exception AuthClientException."), HttpServletResponse.SC_BAD_REQUEST,
                        true},
                {new AuthServerException("Test exception AuthServerException."), HttpServletResponse.SC_BAD_REQUEST,
                        true},
                { new AuthenticationFailException("Test exception AuthenticationFailException."),
                  HttpServletResponse.SC_UNAUTHORIZED, true},
                { new AuthRuntimeException("Test exception AuthRuntimeException."),
                  HttpServletResponse.SC_UNAUTHORIZED, true},
                { new AuthClientException("Test exception AuthClientException."), HttpServletResponse.SC_BAD_REQUEST,
                        false},
                { new AuthServerException("Test exception AuthServerException."), HttpServletResponse.SC_BAD_REQUEST,
                        false},
                { new AuthenticationFailException("Test exception AuthenticationFailException."),
                        HttpServletResponse.SC_UNAUTHORIZED, false},
                { new AuthRuntimeException("Test exception AuthRuntimeException."),
                        HttpServletResponse.SC_UNAUTHORIZED, false}
        };
    }

    @DataProvider
    public Object[][] getUnclearedThreadLocalData() {
        return new Object[][]{
                {true}, {false}
        };
    }

    @BeforeMethod
    public void setUp() throws Exception {

        mockStatic(IdentityConfigParser.class);
        Map<String, Object> mockConfig = new HashMap<>();
        List<String> contextualParam = new ArrayList<>();
        contextualParam.add(CONFIG_LOG_PARAM_USER_AGENT);
        contextualParam.add(CONFIG_LOG_PARAM_REMOTE_ADDRESS);
        mockConfig.put(CONFIG_CONTEXTUAL_PARAM, contextualParam);
        when(IdentityConfigParser.getInstance()).thenReturn(mockConfigParser);
        when(mockConfigParser.getConfiguration()).thenReturn(mockConfig);

        authenticationValve = new AuthenticationValve();

        MockitoAnnotations.initMocks(this);
        mockStatic(AuthHandlerManager.class);
        mockStatic(AuthenticationManager.class);

        when(AuthHandlerManager.getInstance()).thenReturn(authHandlerManager);
        when(authHandlerManager.getAuthenticationManager()).thenReturn(authenticationManager);

        when(request.getRequestURI()).thenReturn(DUMMY_RESOURCE);
        when(request.getMethod()).thenReturn(HTTP_METHOD_POST);
        when(request.getAttributeNames()).thenReturn(new Enumeration<String>() {
            @Override
            public boolean hasMoreElements() {
                return false;
            }

            @Override
            public String nextElement() {
                return null;
            }
        });
        List<String> headers = new ArrayList<>();
        IteratorEnumeration iteratorEnumeration = new IteratorEnumeration();
        iteratorEnumeration.setIterator(headers.iterator());
        when(request.getHeaderNames()).thenReturn(iteratorEnumeration);
        when(authenticationManager.getSecuredResource(new ResourceConfigKey(DUMMY_RESOURCE, HTTP_METHOD_POST)))
                .thenReturn(securedResourceConfig);
        when(authHandlerManager.getRequestBuilder(request, response)).
                thenReturn(AuthenticationRequestBuilderFactory.getInstance());

        mockIdentityTenantUtility();
        setCarbonHome();
        mockCarbonContextForTenant(SUPER_TENANT_ID, SUPER_TENANT_DOMAIN_NAME);
        mockRealmService(true);
    }

    @Test(dataProvider = "getExceptionTypeData")
    public void testInvokeException(Exception exception, int statusCode, boolean hasThreadLocal) throws Exception {

        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        when(securedResourceConfig.isSecured()).thenReturn(true);
        when(authenticationManager.authenticate(Matchers.any(AuthenticationContext.class))).thenThrow(exception);
        final int[] errorStatusCode = mockErrorStatusCode();
        invokeAuthenticationValve();
        Assert.assertNotNull(errorStatusCode[0]);
        Assert.assertEquals(errorStatusCode[0], statusCode);
    }

    @Test(dataProvider = "getUnclearedThreadLocalData")
    public void testInvokeForNonSecuredResource(boolean hasThreadLocal) throws Exception {

        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        when(securedResourceConfig.isSecured()).thenReturn(false);
        final Map<String, Object> attributes = mockAttributeMap();
        invokeAuthenticationValve();
        AuthenticationContext authContext = (AuthenticationContext) attributes.get(AUTH_CONTEXT);
        Assert.assertNull(authContext);
    }

    @Test(dataProvider = "getUnclearedThreadLocalData")
    public void testInvokeForSecuredResourceInFail(boolean hasThreadLocal) throws Exception {

        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        when(securedResourceConfig.isSecured()).thenReturn(true);
        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.NOTSECURED);
        when(authenticationManager.authenticate(Matchers.any(AuthenticationContext.class))).thenReturn
                (authenticationResult);
        final Map<String, Object> attributes = mockAttributeMap();
        invokeAuthenticationValve();
        AuthenticationContext authContext = (AuthenticationContext) attributes.get(AUTH_CONTEXT);
        Assert.assertNull(authContext);
    }

    @Test(dataProvider = "getUnclearedThreadLocalData")
    public void testInvokeForSecuredResourceInSuccess(boolean hasThreadLocal) throws Exception {

        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        when(securedResourceConfig.isSecured()).thenReturn(true);
        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.SUCCESS);
        when(authenticationManager.authenticate(Matchers.any(AuthenticationContext.class))).thenReturn
                (authenticationResult);
        final Map<String, Object> attributes = mockAttributeMap();
        invokeAuthenticationValve();
        AuthenticationContext authContext = (AuthenticationContext) attributes.get(AUTH_CONTEXT);
        Assert.assertNotNull(authContext);
    }

    @Test(dataProvider = "getUnclearedThreadLocalData")
    public void testInvokeForContextualParam(boolean hasThreadLocal) throws Exception {

        when(request.getHeader(USER_AGENT)).thenReturn(USER_AGENT);
        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        when(securedResourceConfig.isSecured()).thenReturn(true);
        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.SUCCESS);
        when(authenticationManager.authenticate(Matchers.any(AuthenticationContext.class))).thenReturn
                (authenticationResult);
        invokeAuthenticationValve();
        Assert.assertEquals(MDC.get(USER_AGENT), USER_AGENT);
    }

    @Test(dataProvider = "getUnclearedThreadLocalData")
    public void testInvokeForInvalidTenantDomain(boolean hasThreadLocal) throws Exception {

        mockRealmService(false);
        AuthenticationValveDataHolder.getInstance().setInvalidTenantDomainErrorPage("errorPage");
        PrintWriter printWriter = mock(PrintWriter.class);
        when(response.getWriter()).thenReturn(printWriter);
        final Map<String, Object> attributes = mockAttributeMap();
        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        invokeAuthenticationValve();
        AuthenticationContext authContext = (AuthenticationContext) attributes.get(AUTH_CONTEXT);
        Assert.assertNull(authContext);
    }

    @Test
    public void testInvokeForUnclearedThreadLocal() throws Exception {

        setIdentityErrorThreadLocal();
        invokeAuthenticationValve();
        Assert.assertNull(IdentityUtil.getIdentityErrorMsg());
    }

    private void setIdentityErrorThreadLocal() {

        IdentityErrorMsgContext errorMsgContext = new IdentityErrorMsgContext("mockErrorCode");
        IdentityUtil.setIdentityErrorMsg(errorMsgContext);
    }

    private void invokeAuthenticationValve() throws IOException, ServletException {
        doNothing().when(valve).invoke(request, response);
        authenticationValve.setNext(valve);
        authenticationValve.invoke(request, response);
    }

    private Map<String, Object> mockAttributeMap() {
        final Map<String, Object> attributes = new HashMap<>();
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                Object value = invocation.getArguments()[1];
                attributes.put(key, value);
                return null;
            }
        }).when(request).setAttribute(Matchers.anyString(), Matchers.any());
        return attributes;
    }

    private int[] mockErrorStatusCode() throws Exception {
        final int[] errorStatusCode = new int[1];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                errorStatusCode[0] = (int) invocation.getArguments()[0];
                return null;
            }
        }).when(response).sendError(Matchers.anyInt());
        return errorStatusCode;
    }
}
