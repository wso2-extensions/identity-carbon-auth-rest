package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.catalina.connector.Request;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
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
import org.wso2.carbon.identity.core.bean.context.MessageContext;
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

    private static final String TEST_TENANT_ID = "1";
    private static final String TEST_TENANT_DOMAIN = "test.com";

    @BeforeClass
    public void init() {

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

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticate_InvalidHeaderFormat() throws AuthenticationFailException {

        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("InvalidHeader");
        basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailException.class)
    public void testDoAuthenticate_InvalidCredentialsFormat() throws AuthenticationFailException {

        String authHeader = "Basic " + Base64.encodeBase64String("alice".getBytes(StandardCharsets.UTF_8));
        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
        basicAuthenticationHandler.doAuthenticate(mockAuthenticationContext);
    }

    private static class DummyRequest extends Request {

        private final String requestURI;

        public DummyRequest(String requestURI) {

            super(null);
            this.requestURI = requestURI;
        }

        @Override
        public String getRequestURI() {
            return requestURI;
        }
    }
}
