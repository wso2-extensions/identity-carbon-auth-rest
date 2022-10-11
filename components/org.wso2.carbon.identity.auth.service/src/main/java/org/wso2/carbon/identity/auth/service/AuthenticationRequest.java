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

import org.apache.catalina.connector.Request;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.Cookie;

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

    private static final Log log = LogFactory.getLog(AuthenticationRequest.class);

    protected Map<String, Object> attributes = new HashMap<>();
    protected Map<String, String> headers = new HashMap<>();
    protected Map<CookieKey, Cookie> cookies = new HashMap<>();
    protected Map<CookieKey, List<Cookie>> cookieListMap = new HashMap<>();
    protected String contextPath;
    protected String method;
    protected String requestUri;
    private Request request;

    protected AuthenticationRequest(AuthenticationRequestBuilder builder) {
        this.attributes = builder.attributes;
        this.headers = builder.headers;
        this.cookies = builder.cookies;
        this.cookieListMap = builder.cookieListMap;
        this.contextPath = builder.contextPath;
        this.method = builder.method;
        this.requestUri = builder.requestUri;
        this.request = builder.request;
    }

    public Map<String, Object> getAttributeMap() {
        return Collections.unmodifiableMap(attributes);
    }

    public Enumeration<String> getAttributeNames() {
        return Collections.enumeration(attributes.keySet());
    }

    public Object getAttribute(String name) {
        return attributes.get(name);
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

    public Request getRequest() {

        return request;
    }

    public void setRequest(Request request) {

        this.request = request;
    }

    @Deprecated
    public Map<CookieKey, Cookie> getCookieMap() {
        return Collections.unmodifiableMap(cookies);
    }

    public Map<CookieKey, List<Cookie>> getCookieListMap() {
        return Collections.unmodifiableMap(cookieListMap);
    }

    public Cookie[] getCookies() {
        Collection<List<Cookie>>  cookieListCollection = getCookieListMap().values();
        Collection<Cookie> cookies = new ArrayList<>();
        for (List<Cookie> cookieList : cookieListCollection) {
            cookies.addAll(cookieList);
        }
        return cookies.toArray(new Cookie[cookies.size()]);
    }

    public String getRequestUri() {
        return requestUri;
    }

    public String getContextPath() {
        return contextPath;
    }

    public String getMethod() {
        return method;
    }

    public static class AuthenticationRequestBuilder {

        public Map<String, Object> attributes = new HashMap<>();
        private Map<String, String> headers = new HashMap<>();
        private Map<CookieKey, Cookie> cookies = new HashMap<>();
        private Map<CookieKey, List<Cookie>> cookieListMap = new HashMap<>();
        private String contextPath;
        private String method;
        private String requestUri;
        private Request request;

        public AuthenticationRequestBuilder() {

        }

        public AuthenticationRequestBuilder setMethod(String method) {
            this.method = method;
            return this;
        }

        public AuthenticationRequestBuilder setContextPath(String contextPath) {
            this.contextPath = getNormalizedURI(contextPath);
            return this;
        }

        public AuthenticationRequestBuilder addAttribute(String name, Object value) {
            if ( this.attributes.containsKey(name) ) {
                throw new AuthRuntimeException("Attributes map trying to override existing " +
                        "attribute " + name);
            }
            this.attributes.put(name, value);
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
                log.warn("Overriding existing cookie '" + cookieKey.toString() + "' in cookie map");
            }
            this.cookies.put(cookieKey, value);

            List<Cookie> cookieValues;
            if ( this.cookieListMap.containsKey(cookieKey) ) {
                cookieValues = this.cookieListMap.get(cookieKey);
            } else {
                cookieValues = new ArrayList<>();
            }
            cookieValues.add(value);
            this.cookieListMap.put(cookieKey, cookieValues);
            return this;
        }

        public AuthenticationRequestBuilder setRequestUri(String requestUri) {
            this.requestUri = getNormalizedURI(requestUri);
            return this;
        }

        public AuthenticationRequestBuilder setRequest(Request request) {

            this.request = request;
            return this;
        }

        public AuthenticationRequest build() {
            return new AuthenticationRequest(this);
        }
        private String getNormalizedURI(String path) {
            try {
                return AuthConfigurationUtil.getInstance().getNormalizedRequestURI(path);
            } catch (URISyntaxException | UnsupportedEncodingException e) {
                throw new AuthRuntimeException("Error normalizing URL path: " + path, e);
            }
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

            if ( name != null ? !name.equals(cookieKey.name) : cookieKey.name != null ) return false;
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
