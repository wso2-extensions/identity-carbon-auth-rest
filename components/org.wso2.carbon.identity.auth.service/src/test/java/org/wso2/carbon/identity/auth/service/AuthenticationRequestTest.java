/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.auth.service;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;

import java.net.HttpCookie;

import static org.testng.Assert.*;

/**
 * Test class for authentication request
 */
public class AuthenticationRequestTest {

    @Test
    public void testGetAttributeMap() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();
        assertNotNull(request.getAttributeMap());
    }

    private AuthenticationRequest.AuthenticationRequestBuilder createTestBuilder() {
        AuthenticationRequest.AuthenticationRequestBuilder builder = new AuthenticationRequest.AuthenticationRequestBuilder();
        builder.addHeader("Header1", "Value1");
        builder.addAttribute("Attribute1", "Value1");
        builder.setContextPath("/test/context/path");
        builder.setMethod("GET");

        HttpCookie httpCookie1 = new HttpCookie("cookie1", "cValue1");
        HttpCookie httpCookie2 = new HttpCookie("cookie2", "cValue2");
        AuthenticationRequest.CookieKey cookieKey1 = new AuthenticationRequest.CookieKey(httpCookie1.getName(), "/");
        AuthenticationRequest.CookieKey cookieKey2 = new AuthenticationRequest.CookieKey(httpCookie2.getName(),
                "/foo/bar");

        builder.addCookie(cookieKey1, httpCookie1);
        builder.addCookie(cookieKey2, httpCookie2);
        return builder;
    }

    @Test
    public void testGetAttribute() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertEquals(request.getAttribute("Attribute1"), "Value1");
    }

    @Test
    public void testGetHeaderMap() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertNotNull(request.getHeaderMap());
        assertEquals(request.getHeaderMap().size(), 1);
    }

    @Test
    public void testGetHeaders() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertNotNull(request.getHeaders("Header1"));
        assertEquals(request.getHeaders("Header1").size(), 1);
        assertEquals(request.getHeaders("noHeader").size(), 0);
    }

    @Test
    public void testGetHeaderNames() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertNotNull(request.getHeaderNames());
        assertEquals(request.getHeaderNames().size(), 1);
    }

    @Test
    public void testGetHeader() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertEquals(request.getHeader("Header1"), "Value1");
        assertEquals(request.getHeader("header1"), "Value1");
        assertNull(request.getHeader(null));
    }

    @Test
    public void testGetCookieMap() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertNotNull(request.getCookieMap());
        assertEquals(request.getCookieMap().size(), 2);
    }

    @Test
    public void testGetCookies() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertNotNull(request.getCookies());
        assertEquals(request.getCookies().size(), 2);
    }

    @Test
    public void testGetContextPath() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertNotNull(request.getContextPath(), "/test/context/path");
    }

    @Test
    public void testGetMethod() throws Exception {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();
        AuthenticationRequest request = builder.build();

        assertNotNull(request.getMethod(), "GET");
    }

    @Test
    public void testAddWothNoDuplicates() {
        AuthenticationRequest.AuthenticationRequestBuilder builder = createTestBuilder();

        try {
            builder.addHeader("Header1", "Value1");
            fail("There should be an exception failing the duplicate addition");
        }catch (AuthRuntimeException re) {
            assertTrue(true);
        }

        try {
            HttpCookie httpCookie1 = new HttpCookie("cookie1", "cValue1");
            AuthenticationRequest.CookieKey cookieKey1 = new AuthenticationRequest.CookieKey(httpCookie1.getName(), "/");
            builder.addCookie(cookieKey1, httpCookie1);
            fail("There should be an exception failing the duplicate addition");
        }catch (AuthRuntimeException re) {
            assertTrue(true);
        }
        try {
            builder.addAttribute("Attribute1", "Value1");
            fail("There should be an exception failing the duplicate addition");
        }catch (AuthRuntimeException re) {
            assertTrue(true);
        }
    }

    @Test
    public void testCookieKeyEquality() throws Exception {
        AuthenticationRequest.CookieKey cookieKey1 = new AuthenticationRequest.CookieKey("cookie1", "/");
        AuthenticationRequest.CookieKey cookieKey2 = new AuthenticationRequest.CookieKey("cookie2", "/foo/bar");

        AuthenticationRequest.CookieKey cookieKey11 = new AuthenticationRequest.CookieKey(cookieKey1.getName(),
                cookieKey1.getPath());
        AuthenticationRequest.CookieKey cookieKey1Not = new AuthenticationRequest.CookieKey(cookieKey1.getName(),
                cookieKey1.getPath() + "not");

        assertEquals(cookieKey1, cookieKey11);
        assertEquals(cookieKey1, cookieKey1);
        assertFalse(cookieKey1.equals(cookieKey2));
        assertFalse(cookieKey1.equals(null));
        assertFalse(cookieKey1.equals(cookieKey1Not));
        assertFalse(cookieKey1.equals("NotTheClass"));
    }
}