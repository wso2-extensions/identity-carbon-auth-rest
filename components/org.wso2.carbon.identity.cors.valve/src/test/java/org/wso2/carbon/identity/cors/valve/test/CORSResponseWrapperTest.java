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

import org.testng.annotations.Test;
import org.wso2.carbon.identity.cors.valve.constant.Header;
import org.wso2.carbon.identity.cors.valve.internal.wrapper.CORSResponseWrapper;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Tests the CORS response wrapper.
 */
public class CORSResponseWrapperTest {

    @Test
    public void testReset() {

        final String otherHeaderName = "X-Other-Header";

        final Map<String, String> headers = new HashMap<>();
        headers.put(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS, "allow-credentials");
        headers.put(Header.ACCESS_CONTROL_ALLOW_HEADERS, "allow-headers");
        headers.put(Header.ACCESS_CONTROL_ALLOW_METHODS, "allow-methods");
        headers.put(Header.ACCESS_CONTROL_ALLOW_ORIGIN, "allow-origin");
        headers.put(Header.ACCESS_CONTROL_EXPOSE_HEADERS, "expose-headers");
        headers.put(Header.ACCESS_CONTROL_MAX_AGE, "max-age");
        headers.put(Header.VARY, "vary");
        headers.put(otherHeaderName, "other-header");

        final MockHttpServletResponse responseMock = new MockHttpServletResponse(headers);

        final CORSResponseWrapper corsResponseWrapper = new CORSResponseWrapper(responseMock);
        corsResponseWrapper.reset();

        assertEquals(headers.get(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS), "allow-credentials");
        assertEquals(headers.get(Header.ACCESS_CONTROL_ALLOW_HEADERS), "allow-headers");
        assertEquals(headers.get(Header.ACCESS_CONTROL_ALLOW_METHODS), "allow-methods");
        assertEquals(headers.get(Header.ACCESS_CONTROL_ALLOW_ORIGIN), "allow-origin");
        assertEquals(headers.get(Header.ACCESS_CONTROL_EXPOSE_HEADERS), "expose-headers");
        assertEquals(headers.get(Header.ACCESS_CONTROL_MAX_AGE), "max-age");
        assertEquals(headers.get(Header.VARY), "vary");
        assertFalse(headers.containsKey(otherHeaderName));
        assertTrue(responseMock.isReset());
    }

    private static final class MockHttpServletResponse implements HttpServletResponse {

        private final Map<String, String> headers;
        private boolean reset;

        MockHttpServletResponse(final Map<String, String> headers) {

            this.headers = headers;
        }

        @Override
        public String getHeader(final String name) {

            return headers.get(name);
        }

        @Override
        public Collection<String> getHeaderNames() {

            return headers.keySet();
        }

        public boolean isReset() {

            return reset;
        }

        @Override
        public void reset() {

            headers.clear();
            reset = true;
        }

        @Override
        public void setHeader(final String name, final String value) {

            headers.put(name, value);
        }

        @Override
        public void addCookie(final Cookie cookie) {

            throw new UnsupportedOperationException();
        }

        @Override
        public void addDateHeader(final String name, final long date) {

            throw new UnsupportedOperationException();
        }

        @Override
        public void addHeader(final String name, final String value) {

            throw new UnsupportedOperationException();
        }

        @Override
        public void addIntHeader(final String name, final int value) {

            throw new UnsupportedOperationException();
        }

        @Override
        public boolean containsHeader(final String name) {

            throw new UnsupportedOperationException();
        }

        @Override
        public String encodeRedirectUrl(final String url) {

            throw new UnsupportedOperationException();
        }

        @Override
        public String encodeRedirectURL(final String url) {

            throw new UnsupportedOperationException();
        }

        @Override
        public String encodeUrl(final String url) {

            throw new UnsupportedOperationException();
        }

        @Override
        public String encodeURL(final String url) {

            throw new UnsupportedOperationException();
        }

        @Override
        public Collection<String> getHeaders(final String name) {

            throw new UnsupportedOperationException();
        }

        @Override
        public int getStatus() {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setStatus(final int sc) {

            throw new UnsupportedOperationException();
        }

        @Override
        public void sendError(final int sc) throws IOException {

            throw new UnsupportedOperationException();
        }

        @Override
        public void sendError(final int sc, final String msg) throws IOException {

            throw new UnsupportedOperationException();
        }

        @Override
        public void sendRedirect(final String location) throws IOException {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setDateHeader(final String name, final long date) {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setIntHeader(final String name, final int value) {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setStatus(final int sc, final String sm) {

            throw new UnsupportedOperationException();
        }

        @Override
        public void flushBuffer() throws IOException {

            throw new UnsupportedOperationException();
        }

        @Override
        public int getBufferSize() {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setBufferSize(final int size) {

            throw new UnsupportedOperationException();
        }

        @Override
        public String getCharacterEncoding() {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setCharacterEncoding(final String charset) {

            throw new UnsupportedOperationException();
        }

        @Override
        public String getContentType() {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setContentType(final String type) {

            throw new UnsupportedOperationException();
        }

        @Override
        public Locale getLocale() {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setLocale(final Locale loc) {

            throw new UnsupportedOperationException();
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {

            throw new UnsupportedOperationException();
        }

        @Override
        public PrintWriter getWriter() throws IOException {

            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isCommitted() {

            throw new UnsupportedOperationException();
        }

        @Override
        public void resetBuffer() {

            throw new UnsupportedOperationException();
        }

        @Override
        public void setContentLength(final int len) {

            throw new UnsupportedOperationException();
        }
    }
}
