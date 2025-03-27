package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.catalina.connector.Request;
import org.apache.http.HttpHeaders;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.validators.TokenValidationHandler;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class OAuth2AccessTokenHandlerTest {

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    @Mock
    private AuthenticationRequest mockAuthenticationRequest;
    @Mock
    private OAuth2TokenValidationService mockOAuth2TokenValidationService;

    @Mock
    private TokenValidationHandler mockTokenValidationHandler;

//    @Mock
//    private Request mockHttpRequest;

    private  MockedStatic<TokenValidationHandler> mockStaticTokenValidationHandler;

    private MockedStatic<OAuthComponentServiceHolder> mockStaticOAuthComponentServiceHolder;

    private OAuth2AccessTokenHandler oAuth2AccessTokenHandler;

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    private OAuthEventInterceptor mockOAuthEventInterceptor;


    @BeforeClass
    public void init() {

        mockStaticTokenValidationHandler = mockStatic(TokenValidationHandler.class);
        mockStaticOAuthComponentServiceHolder = mockStatic(OAuthComponentServiceHolder.class);


    }

    @AfterClass
    public void close() {

       mockStaticTokenValidationHandler.close();
    }

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        oAuth2AccessTokenHandler = new OAuth2AccessTokenHandler();
        when(TokenValidationHandler.getInstance()).thenReturn(mockTokenValidationHandler);

        OAuthComponentServiceHolder mockServiceHolder = mock(OAuthComponentServiceHolder.class);
        when(mockServiceHolder.getOAuthEventInterceptorProxy()).thenReturn(mockOAuthEventInterceptor);
        when(mockOAuthEventInterceptor.isEnabled()).thenReturn(true);

        mockStaticOAuthComponentServiceHolder.when(OAuthComponentServiceHolder::getInstance).thenReturn(mockServiceHolder);


    }

    @Test
    public void testDoAuthenticateWithValidBearerToken() {

        String authorizationHeader = "Bearer validAccessToken";
        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorizationHeader);
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);

        MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                OAuthServerConfiguration.class);
        oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        Map<String, String> tokenValidatorClassNames = new HashMap<>();
        tokenValidatorClassNames.put("default", "org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2TokenValidator");
        oAuthServerConfiguration.when(() -> OAuthServerConfiguration.getInstance().getTokenValidatorClassNames())
                .thenReturn(tokenValidatorClassNames);


        Map<String, Object> properties = new HashMap<>();
        // Add few items into this properties hash map.
        properties.put("key1", "value1");
        properties.put("key2", "value2");
        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = new OAuth2IntrospectionResponseDTO();
        oAuth2IntrospectionResponseDTO.setProperties(properties);
        oAuth2IntrospectionResponseDTO.setActive(true);

        when(TokenValidationHandler.getInstance()).thenReturn(mockTokenValidationHandler);
        mockTokenValidationHandler.addTokenValidator("default", new org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2TokenValidator());
        assertEquals(TokenValidationHandler.getInstance(), mockTokenValidationHandler);

        try {
            when(mockTokenValidationHandler.buildIntrospectionResponse(any())).thenReturn(oAuth2IntrospectionResponseDTO);
        } catch (IdentityOAuth2Exception e) {
            throw new RuntimeException(e);
        }
        when(mockOAuth2TokenValidationService.buildIntrospectionResponse(any())).thenReturn(oAuth2IntrospectionResponseDTO);

        String requestURI = "/api/server/v1/applications";
//        when(mockAuthenticationRequest.getRequest()).thenReturn(mockHttpRequest);
//        when(mockHttpRequest.getRequestURI()).thenReturn(requestURI);

        // Call the method to be tested
        AuthenticationResult result = oAuth2AccessTokenHandler.doAuthenticate(mockAuthenticationContext);

        // Verify the expected outcomes
        assertEquals(result.getAuthenticationStatus().toString(), AuthenticationStatus.SUCCESS.toString());
    }

    @Test
    public void testDoAuthenticateWithInvalidBearerToken() {

        String authorizationHeader = "InvalidHeader";
        when(mockAuthenticationRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorizationHeader);
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);

        // Call the method to be tested
        AuthenticationResult result = oAuth2AccessTokenHandler.doAuthenticate(mockAuthenticationContext);

        // Verify the expected outcomes
        assertEquals(result.getAuthenticationStatus().toString(), AuthenticationStatus.FAILED.toString());
    }
}
