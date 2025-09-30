/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.cors.valve.internal.handler;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.model.Origin;
import org.wso2.carbon.identity.cors.service.CORSManager;
import org.wso2.carbon.identity.cors.valve.constant.Header;
import org.wso2.carbon.identity.cors.valve.internal.CORSValveServiceHolder;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for CORSRequestHandler.
 */
public class CORSRequestHandlerTest {

    private CORSRequestHandler corsRequestHandler;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private CORSManager corsManager;

    @Mock
    private CORSConfiguration corsConfiguration;

    @Mock
    private CORSValveServiceHolder serviceHolder;

    @BeforeClass
    public void init() {

        initPrivilegedCarbonContext();
    }

    private void initPrivilegedCarbonContext() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(MultitenantConstants.SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("testUser");
    }

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
        corsRequestHandler = new CORSRequestHandler();
    }

    @DataProvider(name = "handleActualRequestDataProvider")
    public Object[][] handleActualRequestDataProvider() {
        return new Object[][]{
                // supportsCredentials, allowAnyOrigin, expectedAllowOrigin
                {true, false, ""},
                {true, true, "https://example.com"},
                {false, true, "*"},
                {false, false, ""},
        };
    }

    @Test(dataProvider = "handleActualRequestDataProvider")
    public void testHandleActualRequest(boolean supportsCredentials, boolean allowAnyOrigin,
                                        String expectedAllowOrigin) throws Exception {

        when(corsConfiguration.isSupportsCredentials()).thenReturn(supportsCredentials);
        when(corsConfiguration.isAllowAnyOrigin()).thenReturn(allowAnyOrigin);

        try (MockedStatic<CORSValveServiceHolder> mockedStatic = mockStatic(CORSValveServiceHolder.class)) {
            mockedStatic.when(CORSValveServiceHolder::getInstance).thenReturn(serviceHolder);

            when(serviceHolder.getCorsManager()).thenReturn(corsManager);

            // Default CORS configuration
            when(corsManager.getCORSConfiguration(anyString())).thenReturn(corsConfiguration);
            when(request.getHeader(Header.ORIGIN)).thenReturn("https://example.com");
            when(corsManager.getCORSOrigins(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                    .thenReturn(new Origin[]{});

            corsRequestHandler.handleActualRequest(request, response);

            if (supportsCredentials) {
                verify(response).addHeader(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
            }
            if (StringUtils.isNotEmpty(expectedAllowOrigin)) {
                verify(response).addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, expectedAllowOrigin);
            } else {
                verify(response, never()).addHeader(eq(Header.ACCESS_CONTROL_ALLOW_ORIGIN), anyString());
            }
            if (expectedAllowOrigin.length() > 1) {
                verify(response).addHeader(Header.VARY, "Origin");
            }
        }
    }

    @DataProvider
    public Object[][] testHandleActualRequestWithOriginDataProvider() {
        return new Object[][]{
                // supportsCredentials, allowAnyOrigin, expectedAllowOrigin
                {true, false, "https://example.com"},
                {true, true, "https://example.com"},
                {false, true, "*"},
                {false, false, ""},
        };
    }

    @Test
    public void testHandleActualRequestWithAllowedOrigin(boolean supportsCredentials, boolean allowAnyOrigin,
                                                         String expectedAllowOrigin) throws Exception {

        when(corsConfiguration.isSupportsCredentials()).thenReturn(supportsCredentials);
        when(corsConfiguration.isAllowAnyOrigin()).thenReturn(allowAnyOrigin);

        try (MockedStatic<CORSValveServiceHolder> mockedStatic = mockStatic(CORSValveServiceHolder.class)) {
            mockedStatic.when(CORSValveServiceHolder::getInstance).thenReturn(serviceHolder);

            when(serviceHolder.getCorsManager()).thenReturn(corsManager);

            // Default CORS configuration
            when(corsManager.getCORSConfiguration(anyString())).thenReturn(corsConfiguration);
            when(request.getHeader(Header.ORIGIN)).thenReturn("https://example.com");
            when(corsManager.getCORSOrigins(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                    .thenReturn(new Origin[]{new Origin("https://example.com")});

            corsRequestHandler.handleActualRequest(request, response);

            if (supportsCredentials) {
                verify(response).addHeader(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
            }
            if (StringUtils.isNotEmpty(expectedAllowOrigin)) {
                verify(response).addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, expectedAllowOrigin);
            } else {
                verify(response, never()).addHeader(eq(Header.ACCESS_CONTROL_ALLOW_ORIGIN), anyString());
            }
            if (expectedAllowOrigin.length() > 1) {
                verify(response).addHeader(Header.VARY, "Origin");
            }
        }
    }

    @Test
    public void testHandleActualRequestWithExposedHeaders() throws Exception {

        try (MockedStatic<CORSValveServiceHolder> mockedStatic = mockStatic(CORSValveServiceHolder.class)) {
            mockedStatic.when(CORSValveServiceHolder::getInstance).thenReturn(serviceHolder);

            when(serviceHolder.getCorsManager()).thenReturn(corsManager);

            // Default CORS configuration
            when(corsManager.getCORSConfiguration(anyString())).thenReturn(corsConfiguration);
            when(request.getHeader(Header.ORIGIN)).thenReturn("https://example.com");

            when(corsManager.getCORSOrigins(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                    .thenReturn(new Origin[]{new Origin("https://example.com")});
            when(corsConfiguration.getExposedHeaders())
                    .thenReturn(new HashSet<>(Arrays.asList("X-Custom-Header", "X-Another-Header")));

            corsRequestHandler.handleActualRequest(request, response);

            verify(response).addHeader(Header.ACCESS_CONTROL_EXPOSE_HEADERS, "X-Custom-Header, X-Another-Header");
        }
    }

    @Test
    public void testHandleActualRequestWithSpecificOrigins() throws Exception {

        try (MockedStatic<CORSValveServiceHolder> mockedStatic = mockStatic(CORSValveServiceHolder.class)) {
            mockedStatic.when(CORSValveServiceHolder::getInstance).thenReturn(serviceHolder);

            when(serviceHolder.getCorsManager()).thenReturn(corsManager);

            // Default CORS configuration
            when(corsManager.getCORSConfiguration(anyString())).thenReturn(corsConfiguration);
            when(request.getHeader(Header.ORIGIN)).thenReturn("https://example.com");

            when(corsManager.getCORSOrigins(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                    .thenReturn(new Origin[]{new Origin("https://example.com")});
            when(corsConfiguration.isSupportsCredentials()).thenReturn(false);
            when(corsConfiguration.isAllowAnyOrigin()).thenReturn(false);

            corsRequestHandler.handleActualRequest(request, response);

            verify(response).addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, "https://example.com");
            verify(response).addHeader(Header.VARY, "Origin");
        }
    }
}
