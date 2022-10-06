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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.collections.iterators.IteratorEnumeration;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
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
import java.io.StringWriter;
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
import static org.wso2.carbon.identity.auth.service.util.Constants.IDP_NAME;
import static org.wso2.carbon.identity.auth.service.util.Constants.IS_FEDERATED_USER;
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
    private static final String REMOTE_ADDRESS = "remoteAddress";
    private static final String SERVICE_PROVIDER = "serviceProvider";
    private static final String CLIENT_COMPONENT = "clientComponent";
    private static final String IDP = "GOOGLE";
    private final String CONFIG_CONTEXTUAL_PARAM = "LoggableContextualParams.contextual_param";
    private final String CONFIG_LOG_PARAM_USER_AGENT = "user_agent";
    private final String CONFIG_LOG_PARAM_REMOTE_ADDRESS = "remote_address";
    private static final String UN_NORMALIZED_DUMMY_RESOURCE = "/./test/resource";

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

    private StringWriter stringWriter;

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
    public Object[][] getRequestContentTypeAndCustomErrorPagesForInvalidTenantResponse() {

        /*
        Content-Type of request, error page content if default_error_page_of_invalid_tenant_domain_response.html file found,
        unclear thread local data.
         */
        return new Object[][]{
                {"application/json", "<p>$error.msg</p>", true},
                {"application/json", "<p>$error.msg</p>", false},
                {"application/json", null, true},
                {"application/json", null, false},
                {"text/html", "<p>$error.msg</p>", true},
                {"text/html", "<p>$error.msg</p>", false},
                {"text/html", null, true},
                {"text/html", null, false},
        };
    }

    @DataProvider
    public Object[][] getUnclearedThreadLocalData() {

        return new Object[][]{
                {true}, {false}
        };
    }

    @DataProvider
    public Object[][] getAPIResponseExceptionData() {

        return new Object[][]{ //Exception, Status Code
                {new AuthClientException("Test exception AuthClientException."), HttpServletResponse.SC_BAD_REQUEST},
                { new AuthenticationFailException("Test exception AuthServerException."),
                        HttpServletResponse.SC_UNAUTHORIZED,},
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
        stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);
    }

    @Test(dataProvider = "getExceptionTypeData")
    public void testInvokeException(Exception exception, int statusCode, boolean hasThreadLocal) throws Exception {

        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        when(securedResourceConfig.isSecured()).thenReturn(true);
        when(authenticationManager.authenticate(ArgumentMatchers.any(AuthenticationContext.class))).thenThrow(exception);
        invokeAuthenticationValve();
        JsonObject jsonObject = getJsonResponseBody();
        Assert.assertEquals(jsonObject.get("code").getAsInt(), statusCode);
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
        when(authenticationManager.authenticate(ArgumentMatchers.any(AuthenticationContext.class))).thenReturn
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
        when(authenticationManager.authenticate(ArgumentMatchers.any(AuthenticationContext.class))).thenReturn
                (authenticationResult);
        final Map<String, Object> attributes = mockAttributeMap();
        invokeAuthenticationValve();
        AuthenticationContext authContext = (AuthenticationContext) attributes.get(AUTH_CONTEXT);
        Assert.assertNotNull(authContext);
    }

    @Test(dataProvider = "getUnclearedThreadLocalData")
    public void testInvokeForClearedMDCParams(boolean hasThreadLocal) throws Exception {

        when(request.getHeader(USER_AGENT)).thenReturn(USER_AGENT);
        when(request.getRemoteAddr()).thenReturn(REMOTE_ADDRESS);
        if (hasThreadLocal) {
            setIdentityErrorThreadLocal();
        }
        when(securedResourceConfig.isSecured()).thenReturn(true);
        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.SUCCESS);
        when(authenticationManager.authenticate(ArgumentMatchers.any(AuthenticationContext.class))).thenReturn
                (authenticationResult);
        invokeAuthenticationValve();
        Assert.assertNull(MDC.get(USER_AGENT));
        Assert.assertNull(MDC.get(REMOTE_ADDRESS));
    }

    @Test(dataProvider = "getRequestContentTypeAndCustomErrorPagesForInvalidTenantResponse")
    public void testInvokeForInvalidTenantDomain(String requestContentType, String errorPage,
                                                           boolean hasThreadLocal) throws Exception {

        mockRealmService(false);
        AuthenticationValveDataHolder.getInstance().setInvalidTenantDomainErrorPage(errorPage);
        PrintWriter printWriter = mock(PrintWriter.class);
        when(response.getWriter()).thenReturn(printWriter);
        when(request.getContentType()).thenReturn(requestContentType);
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
        setIdentityThreadLocalForFederatedUsers();
        invokeAuthenticationValve();
        Assert.assertNull(IdentityUtil.getIdentityErrorMsg());
        Assert.assertNull(IdentityUtil.threadLocalProperties.get().get(IS_FEDERATED_USER));
        Assert.assertNull(IdentityUtil.threadLocalProperties.get().get(IDP_NAME));
    }

    @Test(dataProvider = "getAPIResponseExceptionData")
    public void testHandlingSCIM2APIErrorResponses(Exception e, int statusCode)
            throws Exception {
        String scimEndpoint = "/scim2/me";
        when(authenticationManager.getSecuredResource(new ResourceConfigKey(scimEndpoint, HTTP_METHOD_POST)))
                .thenReturn(securedResourceConfig);
        when(request.getRequestURI()).thenReturn(scimEndpoint);
        when(response.getRequest()).thenReturn(request);
        when(securedResourceConfig.isSecured()).thenReturn(true);
        when(authenticationManager.authenticate(ArgumentMatchers.any(AuthenticationContext.class))).thenThrow(e);
        invokeAuthenticationValve();
        JsonObject jsonObject = getJsonResponseBody();
        Assert.assertEquals(statusCode, jsonObject.get("status").getAsInt());
    }

    @Test
    public void testHandlingDCRAPIErrorResponseForBadRequest()
            throws Exception {
        String scimEndpoint = "/api/identity/oauth2/dcr/test";
        when(authenticationManager.getSecuredResource(new ResourceConfigKey(scimEndpoint, HTTP_METHOD_POST)))
                .thenReturn(securedResourceConfig);
        when(request.getRequestURI()).thenReturn(scimEndpoint);
        when(response.getRequest()).thenReturn(request);
        when(securedResourceConfig.isSecured()).thenReturn(true);
        when(authenticationManager.authenticate(ArgumentMatchers.any(AuthenticationContext.class))).thenThrow(new AuthClientException());
        invokeAuthenticationValve();
        JsonObject jsonObject = getJsonResponseBody();
        Assert.assertEquals("invalid_client_metadata", jsonObject.get("error").getAsString());
    }

    @Test
    public void testHandlingDCRAPIErrorResponseForUnAuthorizedError()
            throws Exception {
        String scimEndpoint = "/dcr/test";
        when(authenticationManager.getSecuredResource(new ResourceConfigKey(scimEndpoint, HTTP_METHOD_POST)))
                .thenReturn(securedResourceConfig);
        when(request.getRequestURI()).thenReturn(scimEndpoint);
        when(response.getRequest()).thenReturn(request);
        when(securedResourceConfig.isSecured()).thenReturn(true);
        when(authenticationManager.authenticate(ArgumentMatchers.any(AuthenticationContext.class))).thenThrow(
                new AuthenticationFailException());
        invokeAuthenticationValve();
        JsonObject jsonObject = getJsonResponseBody();
        Assert.assertEquals(401, jsonObject.get("code").getAsInt());
    }

    @Test
    public void testInvokeWithUnNormalizedURL() throws Exception {

        when(request.getRequestURI()).thenReturn(UN_NORMALIZED_DUMMY_RESOURCE);
        invokeAuthenticationValve();
        final Map<String, Object> attributes = mockAttributeMap();
        AuthenticationContext authContext = (AuthenticationContext) attributes.get(AUTH_CONTEXT);
        Assert.assertNull(authContext);
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
        }).when(request).setAttribute(ArgumentMatchers.anyString(), ArgumentMatchers.any());
        return attributes;
    }

    private JsonObject getJsonResponseBody() {
        JsonElement parser = new JsonParser().parse(stringWriter.toString());
        return parser.getAsJsonObject();
    }

    private void setIdentityThreadLocalForFederatedUsers() {

        IdentityUtil.threadLocalProperties.get().put(IS_FEDERATED_USER, true);
        IdentityUtil.threadLocalProperties.get().put(IDP_NAME, IDP);
    }
}
