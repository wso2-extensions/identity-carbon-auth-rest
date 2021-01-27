/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.cors.valve.test;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.cors.valve.constant.Header;
import org.wso2.carbon.identity.cors.valve.internal.util.HeaderUtils;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

/**
 * Tests the header utilities.
 */
public class HeaderUtilsTest {

    @Test
    public void testConstants() {

        assertEquals(Header.ORIGIN, "Origin");
        assertEquals(Header.ACCESS_CONTROL_REQUEST_METHOD, "Access-Control-Request-Method");
        assertEquals(Header.ACCESS_CONTROL_REQUEST_HEADERS, "Access-Control-Request-Headers");
        assertEquals(Header.ACCESS_CONTROL_ALLOW_ORIGIN, "Access-Control-Allow-Origin");
        assertEquals(Header.ACCESS_CONTROL_ALLOW_METHODS, "Access-Control-Allow-Methods");
        assertEquals(Header.ACCESS_CONTROL_ALLOW_HEADERS, "Access-Control-Allow-Headers");
        assertEquals(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS, "Access-Control-Allow-Credentials");
        assertEquals(Header.ACCESS_CONTROL_MAX_AGE, "Access-Control-Max-Age");
        assertEquals(Header.ACCESS_CONTROL_EXPOSE_HEADERS, "Access-Control-Expose-Headers");
        assertEquals(Header.ACCESS_CONTROL_EXPOSE_HEADERS, "Access-Control-Expose-Headers");
        assertEquals(Header.VARY, "Vary");
        assertEquals(Header.HOST, "Host");
    }

    @Test
    public void testFormatCanonical1() {

        assertEquals(HeaderUtils.formatCanonical("content-type"), "Content-Type");
    }

    @Test
    public void testFormatCanonical2() {

        assertEquals(HeaderUtils.formatCanonical("CONTENT-TYPE"), "Content-Type");
    }

    @Test
    public void testFormatCanonical3() {

        assertEquals(HeaderUtils.formatCanonical("X-type"), "X-Type");
    }

    @Test
    public void testFormatCanonical4() {

        assertEquals(HeaderUtils.formatCanonical("Origin"), "Origin");
    }

    @Test
    public void testFormatCanonical5() {

        assertEquals(HeaderUtils.formatCanonical("A"), "A");
    }

    @Test
    public void testFormatCanonical6() {

        try {
            assertEquals(HeaderUtils.formatCanonical(""), "");
            fail("Failed to raise IllegalArgumentException on empty string");

        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    @Test
    public void testTrim() {

        String expected = "Content-Type";
        String n1 = HeaderUtils.formatCanonical("content-type\n");
        String n2 = HeaderUtils.formatCanonical(" CONTEnt-Type ");

        assertEquals(n1, expected, "All whitespace should be trimmed");
        assertEquals(n2, expected, "All whitespace should be trimmed");
    }

    @Test
    public void testInvalid1() {

        assertInvalid("X-r@b");
    }

    @Test
    public void testInvalid2() {

        assertInvalid("1=X-r");
    }

    @Test
    public void testInvalid3() {

        assertInvalid("Aaa Bbb");
    }

    @Test
    public void testInvalid4() {

        assertInvalid("less<than");
    }

    @Test
    public void testInvalid5() {

        assertInvalid("alpha1>");
    }

    @Test
    public void testInvalid6() {

        assertInvalid("X-Forwarded-By-{");
    }

    @Test
    public void testInvalid7() {

        assertInvalid("a}");
    }

    @Test
    public void testInvalid8() {

        assertInvalid("separator:");
    }

    @Test
    public void testInvalid9() {

        assertInvalid("asd\"f;");
    }

    @Test
    public void testInvalid10() {

        assertInvalid("rfc@w3c.org");
    }

    @Test
    public void testInvalid11() {

        assertInvalid("bracket[");
    }

    @Test
    public void testInvalid12() {

        assertInvalid("control\u0002header");
    }

    @Test
    public void testInvalid13() {

        assertInvalid("control\nembedded");
    }

    @Test
    public void testInvalid14() {

        assertInvalid("uni╚(•⌂•)╝");
    }

    @Test
    public void testInvalid15() {

        assertInvalid("uni\u3232_\u3232");
    }

    @Test
    public void testUnusualButValid() {

        HeaderUtils.formatCanonical("__2");
        HeaderUtils.formatCanonical("$%.%");
        HeaderUtils.formatCanonical("`~'&#*!^|");
        HeaderUtils.formatCanonical("Original_Name");
    }

    private void assertInvalid(String header) {

        try {
            HeaderUtils.formatCanonical(header);
            fail("Failed to raise exeption on bad header name");
        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    @Test
    public void testSerialize() {

        Set<String> values = new LinkedHashSet<String>();
        values.add("apples");
        values.add("pears");
        values.add("oranges");

        String out = HeaderUtils.serialize(values, ", ");

        assertEquals("apples, pears, oranges", out);

        out = HeaderUtils.serialize(values, " ");

        assertEquals("apples pears oranges", out);

        out = HeaderUtils.serialize(values, null);

        assertEquals("applesnullpearsnulloranges", out);
    }

    @Test
    public void testParseMultipleHeaderValues() {

        String[] out = HeaderUtils.parseMultipleHeaderValues(null);

        assertEquals(0, out.length);

        out = HeaderUtils.parseMultipleHeaderValues("apples, pears, oranges");

        assertEquals("apples", out[0]);
        assertEquals("pears", out[1]);
        assertEquals("oranges", out[2]);
        assertEquals(3, out.length);

        out = HeaderUtils.parseMultipleHeaderValues("apples,pears,oranges");

        assertEquals("apples", out[0]);
        assertEquals("pears", out[1]);
        assertEquals("oranges", out[2]);
        assertEquals(3, out.length);

        out = HeaderUtils.parseMultipleHeaderValues("apples pears oranges");

        assertEquals("apples", out[0]);
        assertEquals("pears", out[1]);
        assertEquals("oranges", out[2]);
        assertEquals(3, out.length);
    }

    @DataProvider
    public Object[][] getMediaTypeTestData() {
        return new Object[][] {
                { "multipart/form-data", "multipart/form-data" },
                { "text/html;", "text/html" },
                { "text/html; charset=UTF-8", "text/html" },
                { null, null },
        };
    }

    @Test(dataProvider = "getMediaTypeTestData")
    public void testGetMediaType(String contentType, String mediaType) {

        assertEquals(HeaderUtils.getMediaType(contentType), mediaType);
    }
}
