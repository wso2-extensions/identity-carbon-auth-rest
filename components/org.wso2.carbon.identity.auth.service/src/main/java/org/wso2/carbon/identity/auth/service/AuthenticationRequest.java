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

import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;

import java.io.Serializable;
import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Generic Request object to pass the request details to the AuthenticationManager.
 * We have to create AuthenticationRequestBuilder and fill the data. Then you can call the build method.
 * AuthenticationRequestConstants can be used to refer the constants.
 *
 * AuthenticationRequest.AuthenticationRequestBuilder requestBuilder = new AuthenticationRequest
 * .AuthenticationRequestBuilder();
 * requestBuilder.set...
 * <code>
 * AuthenticationRequest request = requestBuilder.build();
 * </code>
 */
public class AuthenticationRequest {

    protected Map<String, Object> attributes = new HashMap<>();
    protected Map<String, String> headers = new HashMap<>();
    protected Map<CookieKey, HttpCookie> cookies = new HashMap<>();
    protected String contextPath;
    protected String method;

    protected AuthenticationRequest(AuthenticationRequestBuilder builder) {
        this.attributes = builder.attributes;
        this.headers = builder.headers;
        this.cookies = builder.cookies;
        this.contextPath = builder.contextPath;
        this.method = builder.method;
    }

    public Map<String, Object> getAttributeMap() {
        return Collections.unmodifiableMap(attributes);
    }

    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    public Map<String, String> getHeaderMap() {
        return Collections.unmodifiableMap(headers);
    }

    public List<String> getHeaders(String name) {
        String headerValue = headers.get(name);
        if (headerValue != null) {
            String[] multiValuedHeader = headerValue.split(",");
            return Arrays.asList(multiValuedHeader);
        } else {
            return Collections.emptyList();
        }
    }

    public Collection<String> getHeaderNames() {
        return Collections.unmodifiableCollection(headers.keySet());
    }

    public String getHeader(String name) {
        if (name == null) {
            return null;
        }
        String result = headers.get(name);
        if (result == null) {
            result = headers.keySet().stream()
                    .filter(k -> k.equalsIgnoreCase(name))
                    .map(k -> headers.get(k)).findAny()
                    .orElse(null);
        }
        return result;
    }

    public Map<CookieKey, HttpCookie> getCookieMap() {
        return Collections.unmodifiableMap(cookies);
    }

    public List<HttpCookie> getCookies() {
        Collection<HttpCookie> cookies = getCookieMap().values();
        return new ArrayList<>(cookies);
    }

    public String getContextPath() {
        return contextPath;
    }

    public String getMethod() {
        return method;
    }

    /**
     * Builder Pattern
     */
    public static class AuthenticationRequestBuilder {

        public Map<String, Object> attributes = new HashMap<>();
        private Map<String, String> headers = new HashMap<>();
        private Map<CookieKey, HttpCookie> cookies = new HashMap<>();
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

        public AuthenticationRequestBuilder addAttribute(String name, Object value) {
            if (this.attributes.containsKey(name)) {
                throw new AuthRuntimeException("Attributes map trying to override existing " +
                        "attribute " + name);
            }
            this.attributes.put(name, value);
            return this;
        }

        public AuthenticationRequestBuilder addHeader(String name, String value) {
            if (this.headers.containsKey(name)) {
                throw new AuthRuntimeException("Headers map trying to override existing " +
                        "header " + name);
            }
            this.headers.put(name, value);
            return this;
        }

        public AuthenticationRequestBuilder addCookie(CookieKey cookieKey, HttpCookie value) {
            if (this.cookies.containsKey(cookieKey)) {
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

    /**
     * Key for a HTTP cookie.
     */
    public static class CookieKey implements Serializable {

        private static final long serialVersionUID = -7727473384985073200L;

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
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            CookieKey cookieKey = (CookieKey) o;

            if (name != null ? !name.equals(cookieKey.name) : cookieKey.name != null) {
                return false;
            }
            return !(path != null ? !path.equals(cookieKey.path) : cookieKey.path != null);

        }

        @Override
        public int hashCode() {
            int result = name != null ? name.hashCode() : 0;
            result = 31 * result + (path != null ? path.hashCode() : 0);
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
