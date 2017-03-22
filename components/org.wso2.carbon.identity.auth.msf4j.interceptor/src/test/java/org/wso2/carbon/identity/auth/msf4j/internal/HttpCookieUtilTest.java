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

package org.wso2.carbon.identity.auth.msf4j.internal;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;

import java.net.HttpCookie;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Tests HttpCookieUtil.
 */
public class HttpCookieUtilTest {

    @Test
    public void testDecodeClientCookies_TrickyValues() throws Exception {
        String cookieString1 = "PHPSESSID=d6cb3d4a5e6fd3bbe5078f37d616fac1;, ci_session=a%3A0%3A%7B%7D; , ci_session=a%3A5%3A%7Bs%3A10%3A%22session_id%22%3Bs%3A32%3A%\u200C\u200B22ca963cd5e9b6d9631c\u200C\u200B5afc8f26eb7374%22%3B\u200C\u200Bs%3A10%3A%22ip_addre\u200C\u200Bss%22%3Bs%3A14%3A%22\u200C\u200B182.59.202.107%22%3B\u200C\u200Bs%3A10%3A%22user_age\u200C\u200Bnt%22%3Bs%3A60%3A%22\u200C\u200BDalvik%2F2.1.0+%28Li\u200C\u200Bnux%3B+U%3B+Android+\u200C\u200B5.1.1%3B+Nexus+5+Bui\u200C\u200Bld%2FLMY48B%29%22%3B\u200C\u200Bs%3A13%3A%22last_act\u200C\u200Bivity%22%3Bi%3A14471\u200C\u200B23026%3Bs%3A9%3A%22u\u200C\u200Bser_data%22%3Bs ";
        List<HttpCookie> cookies = HttpCookieUtil.decodeCookies(cookieString1);

        assertEquals(cookies.size(), 3);

        HttpCookie cookie1 = cookies.get(0);
        assertEquals(cookie1.getValue(), "d6cb3d4a5e6fd3bbe5078f37d616fac1");

        HttpCookie cookie2 = cookies.get(1);
        assertEquals(cookie2.getValue(), "a%3A0%3A%7B%7D");

        HttpCookie cookie3 = cookies.get(2);
        assertNotNull(cookie3);
    }

    @Test
    public void testDecodeServerCookie_ComplexAttributes() throws Exception {
        String cookieString = "name=FooBar; expires=Sat, 02 May 2009 23:38:25 GMT; domain=wso2.com; path=/bar";

        HttpCookie cookie1 = HttpCookieUtil.decodeServerCookie(cookieString);
        assertEquals(cookie1.getValue(), "FooBar");

        cookieString = "name=FooBar; Max-Age=20000; domain=wso2.com; path=/bar";
        cookie1 = HttpCookieUtil.decodeServerCookie(cookieString);;
        assertEquals(cookie1.getValue(), "FooBar");

        cookieString = "name=FooBar; Comment=This \"is simple comment";
        cookie1 = HttpCookieUtil.decodeServerCookie(cookieString);;
        assertEquals(cookie1.getComment(), "This \"is simple comment");

        cookieString = "name=FooBar; Secure";
        cookie1 = HttpCookieUtil.decodeServerCookie(cookieString);
        assertTrue(cookie1.getSecure());
    }

    @Test
    public void testDecodeClientCookies() throws Exception {
        String cookieString1 = "name1=value1, name2=value2";
        List<HttpCookie> cookies = HttpCookieUtil.decodeCookies(cookieString1);

        assertEquals(cookies.size(), 2);

        HttpCookie cookie1 = cookies.get(0);
        assertEquals(cookie1.getValue(), "value1");

        HttpCookie cookie2 = cookies.get(1);
        assertEquals(cookie2.getValue(), "value2");
    }

    @Test
    public void testDecodeServerCookie_NoValue() throws Exception {
        String cookieString1 = "name1";
        try {
            HttpCookie cookie = HttpCookieUtil.decodeServerCookie(cookieString1);
            fail("Invalid cookie string should throw an exception");
        } catch (AuthClientException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testDecodeServerCookie_NoAttributeValue() throws Exception {
        String cookieString1 = "name1=value1; MaxAge";
        try {
            HttpCookie cookie = HttpCookieUtil.decodeServerCookie(cookieString1);
            fail("Invalid cookie string should throw an exception");
        } catch (AuthClientException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testDecodeServerCookie_InvalidAttribute() throws Exception {
        String cookieString1 = "name1=value1; foo=bar";
        try {
            HttpCookie cookie = HttpCookieUtil.decodeServerCookie(cookieString1);
            fail("Invalid cookie string should throw an exception");
        } catch (AuthClientException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testDecodeClientCookie_WithQuoteEncoded() throws Exception {
        String cookieString = "name=FooBar; Comment=This \",\"is a comment with comma, name2=value2";
        List<HttpCookie> cookies = HttpCookieUtil.decodeCookies(cookieString);
        assertEquals(cookies.size(), 2);
        assertEquals(cookies.get(0).getComment(), "This \",\"is a comment with comma");
    }
}