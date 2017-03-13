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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Tests for the CookieTest
 */
@Test
public class CookieKeyTest {

    private AuthenticationRequest.CookieKey cookieKey;

    @BeforeMethod
    public void setUp() {
        cookieKey = new AuthenticationRequest.CookieKey("TestKey", "/path/foo");
    }

    @Test
    public void testGetName() throws Exception {
        assertEquals(cookieKey.getName(), "TestKey");
    }

    @Test
    public void testSetName() throws Exception {
        cookieKey.setName("TestKey2");
        assertEquals(cookieKey.getName(), "TestKey2");
    }

    @Test
    public void testGetPath() throws Exception {
        assertEquals(cookieKey.getPath(), "/path/foo");
    }

    @Test
    public void testSetPath() throws Exception {
        cookieKey.setPath("/path/changed");
        assertEquals(cookieKey.getPath(), "/path/changed");
    }

    @Test
    public void testEquals() throws Exception {
        AuthenticationRequest.CookieKey cookieKey2 = new AuthenticationRequest.CookieKey("TestKey", "/path/foo");
        AuthenticationRequest.CookieKey cookieKey3 = new AuthenticationRequest.CookieKey("TestKey",
                "/path-not-match/foo");
        assertEquals(cookieKey2, cookieKey);

        assertNotEquals(cookieKey3, cookieKey);
    }

    @Test
    public void testHashCode() throws Exception {
        assertNotNull(cookieKey.hashCode());
        AuthenticationRequest.CookieKey cookieKey2 = new AuthenticationRequest.CookieKey("TestKey", "/path/foo");
        AuthenticationRequest.CookieKey cookieKey3 = new AuthenticationRequest.CookieKey("TestKey",
                "/path-not-match/foo");

        assertEquals(cookieKey2.hashCode(), cookieKey.hashCode());
        assertNotEquals(cookieKey3.hashCode(), cookieKey.hashCode());
    }

    @Test
    public void testToString() throws Exception {
        AuthenticationRequest.CookieKey cookieKey2 = new AuthenticationRequest.CookieKey("TestKey", "/path/foo");
        AuthenticationRequest.CookieKey cookieKey3 = new AuthenticationRequest.CookieKey("TestKey",
                "/path-not-match/foo");

        assertEquals(cookieKey.toString(), cookieKey2.toString());
        assertNotEquals(cookieKey.toString(), cookieKey3.toString());
    }

}