/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;

import javax.servlet.http.Cookie;
import java.io.Serializable;
import java.util.*;

/**
 * Generic Request object to pass the request details to the AuthenticationManager.
 * We have to create AuthenticationRequestBuilder and fill the data. Then you can call the build method.
 * AuthenticationRequestConstants can be used to refer the constants.
 * <p/>
 * AuthenticationRequest.AuthenticationRequestBuilder requestBuilder = new AuthenticationRequest
 * .AuthenticationRequestBuilder();
 * requestBuilder.set...
 * <p/>
 * AuthenticationRequest request = requestBuilder.build();
 */
public class AuthenticationRequest implements Serializable

{

    private static final long serialVersionUID = 5418537216546873566L;

    protected Map<String, String> headers = new HashMap<>();
    protected Map<CookieKey, Cookie> cookies = new HashMap<>();
    protected String contextPath;
    protected String method;

    protected AuthenticationRequest(AuthenticationRequestBuilder builder) {
        this.headers = builder.headers;
        this.cookies = builder.cookies;
        this.contextPath = builder.contextPath;
        this.method = builder.method;
    }

    public Map<String, String> getHeaderMap() {
        return Collections.unmodifiableMap(headers);
    }

    public Enumeration<String> getHeaders(String name) {
        String headerValue = headers.get(name);
        if ( headerValue != null ) {
            String[] multiValuedHeader = headerValue.split(",");
            return Collections.enumeration(Arrays.asList(multiValuedHeader));
        } else {
            return Collections.emptyEnumeration();
        }
    }

    public Enumeration<String> getHeaderNames() {
        return Collections.enumeration(headers.keySet());
    }

    public String getHeader(String name) {
        if ( StringUtils.isNotEmpty(name) ) {
            name = name.toLowerCase();
        }
        return headers.get(name);
    }

    public Map<CookieKey, Cookie> getCookieMap() {
        return Collections.unmodifiableMap(cookies);
    }

    public Cookie[] getCookies() {
        Collection<Cookie> cookies = getCookieMap().values();
        return cookies.toArray(new Cookie[cookies.size()]);
    }

    public String getContextPath() {
        return contextPath;
    }

    public String getMethod() {
        return method;
    }

    public static class AuthenticationRequestBuilder {

        private Map<String, String> headers = new HashMap<>();
        private Map<CookieKey, Cookie> cookies = new HashMap<>();
        private String contextPath;
        private String method;

        public AuthenticationRequestBuilder() {

        }

        public AuthenticationRequestBuilder setMethod(String method) {
            this.method = method;
            return this;
        }

        public AuthenticationRequestBuilder setContextPath(String contextPath) {
            this.contextPath = contextPath;
            return this;
        }

        public AuthenticationRequestBuilder addHeader(String name, String value) {
            if ( this.headers.containsKey(name) ) {
                throw new AuthRuntimeException("Headers map trying to override existing " +
                        "header " + name);
            }
            this.headers.put(name, value);
            return this;
        }

        public AuthenticationRequestBuilder addCookie(CookieKey cookieKey, Cookie value) {
            if ( this.cookies.containsKey(cookieKey) ) {
                throw new AuthRuntimeException("Cookies map trying to override existing " +
                        "cookie " + cookieKey.toString());
            }
            this.cookies.put(cookieKey, value);
            return this;
        }


        public AuthenticationRequest build() {
            return new AuthenticationRequest(this);
        }


    }


    public static class CookieKey {

        private String name;
        private String path;

        public CookieKey(String name, String path) {
            this.name = name;
            this.path = path;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        @Override
        public boolean equals(Object o) {
            if ( this == o ) return true;
            if ( o == null || getClass() != o.getClass() ) return false;

            CookieKey cookieKey = (CookieKey) o;

            if ( !name.equals(cookieKey.name) ) return false;
            return path.equals(cookieKey.path);

        }

        @Override
        public int hashCode() {
            int result = name.hashCode();
            result = 31 * result + path.hashCode();
            return result;
        }

        @Override
        public String toString() {
            return "CookieKey{" +
                    "name='" + name + '\'' +
                    ", path='" + path + '\'' +
                    '}';
        }
    }

}
