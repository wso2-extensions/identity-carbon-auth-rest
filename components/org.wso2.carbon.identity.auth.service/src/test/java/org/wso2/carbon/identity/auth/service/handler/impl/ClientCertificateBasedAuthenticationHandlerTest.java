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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Unit tests for ClientCertificateBasedAuthenticationHandler.
 * Focus: decision branches, mapping resolution, intermediate-cert mode, and error paths.
 */
public class ClientCertificateBasedAuthenticationHandlerTest {

    private static final String ATTR_CERT = "javax.servlet.request.X509Certificate";
    private static final String HDR_USER = "WSO2-Identity-User";

    @Mock private AuthenticationContext mockAuthCtx;
    @Mock private AuthenticationRequest mockReq;
    @Mock private X509Certificate mockCert;
    @Mock private Principal mockIssuerDN;
    @Mock private Principal mockSubjectDN;

    // Config mappings returned by AuthConfigurationUtil
    @Mock private AuthConfigurationUtil.CertUserMapping mockCertUserMapping;
    @Mock private AuthConfigurationUtil.SystemThumbprintMapping mockSystemMapping;

    private ClientCertificateBasedAuthenticationHandler handler;
    private MockedStatic<AuthConfigurationUtil> staticAuthConfig;
    private AuthConfigurationUtil cfg; // instance returned by getInstance()

    @BeforeClass
    public void beforeClass() {
        MockitoAnnotations.openMocks(this);
        staticAuthConfig = mockStatic(AuthConfigurationUtil.class);
    }

    @AfterClass
    public void afterClass() {
        staticAuthConfig.close();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        handler = new ClientCertificateBasedAuthenticationHandler();

        when(mockAuthCtx.getAuthenticationRequest()).thenReturn(mockReq);
        when(mockReq.getContextPath()).thenReturn("/api/server/v1/applications");

        when(mockReq.getAttribute(ATTR_CERT)).thenReturn(new X509Certificate[]{mockCert});

        when(mockCert.getIssuerDN()).thenReturn(mockIssuerDN);
        when(mockCert.getSubjectDN()).thenReturn(mockSubjectDN);
        when(mockIssuerDN.getName()).thenReturn("CN=RootCA, O=WSO2, C=LK");
        when(mockSubjectDN.getName()).thenReturn("CN=testUser, O=Acme, C=US");

        when(mockCert.getEncoded()).thenReturn("unit-test-cert".getBytes());

        cfg = mock(AuthConfigurationUtil.class);
        staticAuthConfig.when(AuthConfigurationUtil::getInstance).thenReturn(cfg);

        when(cfg.IsClientCertBasedAuthnEnabled()).thenReturn(true);
        when(cfg.isIntermediateCertValidationEnabled()).thenReturn(false);
        when(cfg.getExemptedContextList()).thenReturn(Collections.emptyList());
        when(cfg.getIntermediateCertCNList()).thenReturn(Collections.emptyList());

        when(cfg.getCertUserMappings()).thenReturn(Collections.emptyList());
        when(cfg.getSystemUserThumbprintMappings()).thenReturn(Collections.emptyList());
    }

    @AfterMethod
    public void tearDown() {
        reset(mockAuthCtx, mockReq, mockCert, mockIssuerDN, mockSubjectDN,
                mockCertUserMapping, mockSystemMapping, cfg);
    }


    private static String sha256ThumbprintHexWithColons(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02X:", b));
        if (sb.length() > 0) sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private String computeThumbprintForMock() throws Exception {
        return sha256ThumbprintHexWithColons("unit-test-cert".getBytes());
    }

    private void setUserHeader(String v) {
        when(mockReq.getHeader(HDR_USER)).thenReturn(v);
    }

    private void setNoUserHeader() {
        when(mockReq.getHeader(HDR_USER)).thenReturn(null);
    }


    /** Feature flag ON and certificate attribute present → handler should accept the request. */
    @Test
    public void canHandle_enabledAndCertPresent_returnsTrue() {

        when(cfg.IsClientCertBasedAuthnEnabled()).thenReturn(true);
        assertTrue(handler.canHandle(mockAuthCtx));
    }

    /** Feature flag OFF → handler should refuse even if a cert is present. */
    @Test
    public void canHandle_disabled_returnsFalse() {

        when(cfg.IsClientCertBasedAuthnEnabled()).thenReturn(false);
        assertFalse(handler.canHandle(mockAuthCtx));
    }

    /** Intermediate-cert validation mode alone enables handling regardless of main flag. */
    @Test
    public void canHandle_intermediateModeEnabled_returnsTrue() {

        when(cfg.isIntermediateCertValidationEnabled()).thenReturn(true);
        when(cfg.getExemptedContextList()).thenReturn(Collections.emptyList());
        assertTrue(handler.canHandle(mockAuthCtx));
    }


    /**
     * Exact issuer + exact thumbprint mapping found AND username is in allowed list → SUCCESS.
     * Exercises: mapping resolution, allowed user list check, success path.
     */
    @Test
    public void doAuthenticate_userBased_exactThumbprintAndUsernameAllowed_success() throws Exception {

        String issuer = "CN=RootCA, O=WSO2, C=LK";
        when(mockIssuerDN.getName()).thenReturn(issuer);

        String tp = computeThumbprintForMock();
        setUserHeader("admin@carbon.super");

        when(mockCertUserMapping.getAllowedIssuer()).thenReturn(issuer);
        when(mockCertUserMapping.getAllowedThumbprint()).thenReturn(tp);
        when(mockCertUserMapping.getAllowedUsernames())
                .thenReturn((ArrayList<String>) Arrays.asList("bob", "admin@carbon.super"));

        when(cfg.getCertUserMappings()).thenReturn(Collections.singletonList(mockCertUserMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertNotNull(out);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    /**
     * Exact issuer+thumbprint mapping found and allowed users contain wildcard (*) → SUCCESS
     * regardless of header username value.
     */
    @Test
    public void doAuthenticate_userBased_exactThumbprintWildcardUser_success() throws Exception {

        String issuer = "CN=RootCA, O=WSO2, C=LK";
        when(mockIssuerDN.getName()).thenReturn(issuer);

        String tp = computeThumbprintForMock();
        setUserHeader("anyUser@carbon.super");

        when(mockCertUserMapping.getAllowedIssuer()).thenReturn(issuer);
        when(mockCertUserMapping.getAllowedThumbprint()).thenReturn(tp);
        when(mockCertUserMapping.getAllowedUsernames())
                .thenReturn((ArrayList<String>) Collections.singletonList(Constants.WILDCARD));

        when(cfg.getCertUserMappings()).thenReturn(Collections.singletonList(mockCertUserMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    /**
     * Wildcard thumbprint mapping ("*") and username explicitly listed → SUCCESS.
     * Exercises the fallback when exact thumbprint mapping is absent.
     */
    @Test
    public void doAuthenticate_userBased_wildcardThumbprintAndUserInList_success() throws Exception {

        String issuer = "CN=RootCA, O=WSO2, C=LK";
        when(mockIssuerDN.getName()).thenReturn(issuer);

        setUserHeader("carol@carbon.super");

        when(mockCertUserMapping.getAllowedIssuer()).thenReturn(issuer);
        when(mockCertUserMapping.getAllowedThumbprint()).thenReturn(Constants.WILDCARD);
        when(mockCertUserMapping.getAllowedUsernames())
                .thenReturn((ArrayList<String>) Arrays.asList("alice", "carol@carbon.super"));

        when(cfg.getCertUserMappings()).thenReturn(Collections.singletonList(mockCertUserMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    /**
     * Issuer from certificate is not among trusted issuers configured → FAILED.
     * Exercises issuer allow-list gate for user-based flow.
     */
    @Test
    public void doAuthenticate_userBased_issuerNotTrusted_fails() throws Exception {

        when(mockIssuerDN.getName()).thenReturn("CN=UnknownCA, O=Nowhere");
        setUserHeader("admin@carbon.super");

        when(mockCertUserMapping.getAllowedIssuer()).thenReturn("CN=RootCA, O=WSO2, C=LK");
        when(mockCertUserMapping.getAllowedThumbprint()).thenReturn(Constants.WILDCARD);
        when(mockCertUserMapping.getAllowedUsernames())
                .thenReturn((ArrayList<String>) Collections.singletonList(Constants.WILDCARD));

        when(cfg.getCertUserMappings()).thenReturn(Collections.singletonList(mockCertUserMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.FAILED);
    }

    /**
     * Issuer DNs with different component order normalize equal → SUCCESS.
     * Exercises isDNEqual()/normalizeDN() equivalence handling.
     */
    @Test
    public void doAuthenticate_userBased_issuerOrderDiffers_butEqualAfterNormalization_success() throws Exception {

        setUserHeader("admin@carbon.super");

        String issuerFromCert = "O=WSO2, C=LK, CN=RootCA";
        String issuerInConfig = "CN=RootCA, O=WSO2, C=LK";
        when(mockIssuerDN.getName()).thenReturn(issuerFromCert);

        String tp = computeThumbprintForMock();

        when(mockCertUserMapping.getAllowedIssuer()).thenReturn(issuerInConfig);
        when(mockCertUserMapping.getAllowedThumbprint()).thenReturn(tp);
        when(mockCertUserMapping.getAllowedUsernames())
                .thenReturn((ArrayList<String>) Collections.singletonList(Constants.WILDCARD));

        when(cfg.getCertUserMappings()).thenReturn(Collections.singletonList(mockCertUserMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    /**
     * No user header → system path. Wildcard system user (*) with wildcard thumbprint → SUCCESS
     * and no user is attached to the context (backward-compatible behavior).
     */
    @Test
    public void doAuthenticate_systemBased_wildcardAllowedUser_success_noUserInContext() throws Exception {

        setNoUserHeader();

        String issuer = "CN=RootCA, O=WSO2, C=LK";
        when(mockIssuerDN.getName()).thenReturn(issuer);

        when(mockSystemMapping.getAllowedIssuer()).thenReturn(issuer);
        when(mockSystemMapping.getAllowedThumbprint()).thenReturn(Constants.WILDCARD);
        when(mockSystemMapping.getAllowedSystemUser()).thenReturn(Constants.WILDCARD);

        when(cfg.getSystemUserThumbprintMappings()).thenReturn(Collections.singletonList(mockSystemMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    /**
     * No user header → system path. Exact issuer+thumbprint mapping to a specific system user → SUCCESS.
     * (User gets mapped internally; test asserts successful status.)
     */
    @Test
    public void doAuthenticate_systemBased_mapsToSpecificSystemUser_success() throws Exception {

        setNoUserHeader();

        String issuer = "CN=RootCA, O=WSO2, C=LK";
        when(mockIssuerDN.getName()).thenReturn(issuer);

        String tp = computeThumbprintForMock();
        when(mockSystemMapping.getAllowedIssuer()).thenReturn(issuer);
        when(mockSystemMapping.getAllowedThumbprint()).thenReturn(tp);
        when(mockSystemMapping.getAllowedSystemUser()).thenReturn("SYSTEM/admin@carbon.super");

        when(cfg.getSystemUserThumbprintMappings()).thenReturn(Collections.singletonList(mockSystemMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    /**
     * System path and issuer not trusted → FAILED.
     * Exercises issuer allow-list gate for system flow.
     */
    @Test
    public void doAuthenticate_systemBased_issuerNotTrusted_fails() throws Exception {

        setNoUserHeader();

        when(mockIssuerDN.getName()).thenReturn("CN=UnknownCA");

        when(mockSystemMapping.getAllowedIssuer()).thenReturn("CN=RootCA");
        when(cfg.getSystemUserThumbprintMappings()).thenReturn(Collections.singletonList(mockSystemMapping));

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.FAILED);
    }


    /**
     * Intermediate-cert mode: username is taken from Subject CN and Issuer CN must be in allowed list → SUCCESS.
     */
    @Test
    public void doAuthenticate_intermediateMode_cnMatchesAndIssuerCNAllowed_success() throws Exception {

        when(cfg.isIntermediateCertValidationEnabled()).thenReturn(true);
        when(cfg.getExemptedContextList()).thenReturn(Collections.emptyList());
        when(cfg.getIntermediateCertCNList()).thenReturn(Arrays.asList("RootCA"));

        // Subject CN becomes the username in this mode
        when(mockSubjectDN.getName()).thenReturn("CN=john, O=Acme");
        // Issuer CN must be one of allowed CNs
        when(mockIssuerDN.getName()).thenReturn("CN=RootCA, O=WSO2");

        setUserHeader(null); // header is ignored in this mode

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.SUCCESS);
    }

    /**
     * Intermediate-cert mode: Issuer CN NOT in allowed list → FAILED.
     */
    @Test
    public void doAuthenticate_intermediateMode_issuerCNNotAllowed_fails() throws Exception {

        when(cfg.isIntermediateCertValidationEnabled()).thenReturn(true);
        when(cfg.getIntermediateCertCNList()).thenReturn(Arrays.asList("SomeOtherCA"));

        when(mockSubjectDN.getName()).thenReturn("CN=jane");
        when(mockIssuerDN.getName()).thenReturn("CN=RootCA");

        AuthenticationResult out = handler.doAuthenticate(mockAuthCtx);
        assertEquals(out.getAuthenticationStatus(), AuthenticationStatus.FAILED);
    }


    /** Missing certificate attribute entirely → AuthenticationFailException (attribute null). */
    @Test(expectedExceptions = AuthenticationFailException.class)
    public void doAuthenticate_attributeMissing_throws() throws Exception {

        when(mockReq.getAttribute(ATTR_CERT)).thenReturn(null);
        handler.doAuthenticate(mockAuthCtx);
    }

    /** Wrong attribute type (not X509Certificate[]) → AuthenticationFailException with casting message. */
    @Test
    public void doAuthenticate_invalidAttributeType_throwsCastingMessage() {

        when(mockReq.getAttribute(ATTR_CERT)).thenReturn(new Object());
        try {
            handler.doAuthenticate(mockAuthCtx);
            fail("Expected AuthenticationFailException");
        } catch (AuthenticationFailException e) {
            assertTrue(e.getMessage().contains("Exception while casting"));
        } catch (Exception e) {
            fail("Unexpected exception: " + e);
        }
    }

    /** Empty certificate array → AuthenticationFailException with 'X509Certificate object is null.' message. */
    @Test
    public void doAuthenticate_emptyCertArray_throwsNullMessage() {

        when(mockReq.getAttribute(ATTR_CERT)).thenReturn(new X509Certificate[0]);
        try {
            handler.doAuthenticate(mockAuthCtx);
            fail("Expected AuthenticationFailException");
        } catch (AuthenticationFailException e) {
            assertTrue(e.getMessage().contains("X509Certificate object is null."));
        } catch (Exception e) {
            fail("Unexpected exception: " + e);
        }
    }
}
