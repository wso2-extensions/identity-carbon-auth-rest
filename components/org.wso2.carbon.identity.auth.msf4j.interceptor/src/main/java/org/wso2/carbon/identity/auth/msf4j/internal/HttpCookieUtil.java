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

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;

import java.net.HttpCookie;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Utility class to manipulate HTTP cookies from the HTTP request.
 */
public class HttpCookieUtil {

    /**
     * Decode the HTTP cookie string to its components.
     *
     * @param cookieString  The cookie string to be passed.
     * @return List of decoded HTTP Cookie objects
     * @throws AuthClientException
     */
    public static List<HttpCookie> decodeCookies(String cookieString) throws AuthClientException {
        if (StringUtils.isBlank(cookieString)) {
            return Collections.emptyList();
        }
        List<HttpCookie> result = new ArrayList<>();
        List<String> splits = splitMultiCookies(cookieString);
        for (String s : splits) {
            result.add(parseRawCookie(s));
        }
        return result;
    }

    /**
     * Decodes a "Set-Cookie" header and returns the cookie.
     * @param cookieString
     * @return a parsed HttpCookie
     * @throws AuthClientException when there is an error in parsing.
     */
    public static HttpCookie decodeServerCookie(String cookieString) throws AuthClientException {
        return parseRawCookie(cookieString);
    }

    /**
     * Splits the HTTP Cookie components out of single cookie string.
     * @param header The cookie header.
     * @return List of cookie string.
     */
    private static List<String> splitMultiCookies(String header) {
        List<String> cookies = new java.util.ArrayList<String>();
        int quoteCount = 0;
        int p, q;

        for (p = 0, q = 0; p < header.length(); p++) {
            char c = header.charAt(p);
            if (c == '"') {
                quoteCount++;
            }
            if (c == ',' && (quoteCount % 2 == 0)) {
                // it is comma and not surrounding by double-quotes
                cookies.add(header.substring(q, p));
                q = p + 1;
            }
        }
        cookies.add(header.substring(q));

        return cookies;
    }

    /**
     * Parses the raw cookie string to the Cookie object.
     *
     * @param rawCookie the String representation of a cookie.
     * @return the decoded cookie object.
     * @throws AuthClientException when there is an error reading any component of the cookie.
     */
    private static HttpCookie parseRawCookie(String rawCookie) throws AuthClientException {
        String[] rawCookieParams = rawCookie.split(";");

        String[] rawCookieNameAndValue = rawCookieParams[0].split("=");
        if (rawCookieNameAndValue.length != 2) {
            throw new AuthClientException(
                    "Invalid cookie: missing name and value for cookie. Cookie String: " + rawCookie);
        }

        String cookieName = rawCookieNameAndValue[0].trim();
        String cookieValue = rawCookieNameAndValue[1].trim();
        HttpCookie cookie = new HttpCookie(cookieName, cookieValue);
        for (int i = 1; i < rawCookieParams.length; i++) {
            if (StringUtils.isBlank(rawCookieParams[i])) {
                continue;
            }
            String rawCookieParamNameAndValue[] = rawCookieParams[i].trim().split("=");

            String paramName = rawCookieParamNameAndValue[0].trim();

            if (paramName.equalsIgnoreCase("secure")) {
                cookie.setSecure(true);
            } else {
                if (rawCookieParamNameAndValue.length != 2) {
                    throw new AuthClientException(
                            "Invalid cookie: attribute not a flag or missing value for cookie. Cookie: " + rawCookie);
                }

                String paramValue = rawCookieParamNameAndValue[1].trim();

                if (paramName.equalsIgnoreCase("expires")) {
                    TemporalAccessor temporalAccessor = DateTimeFormatter.RFC_1123_DATE_TIME.parse(paramValue);
                    LocalDateTime expires = LocalDateTime.from(temporalAccessor);
                    LocalDateTime now = LocalDateTime.now();
                    long maxAge = now.until(expires, ChronoUnit.MILLIS);
                    cookie.setMaxAge(maxAge);
                } else if (paramName.equalsIgnoreCase("max-age")) {
                    long maxAge = Long.parseLong(paramValue);
                    cookie.setMaxAge(maxAge);
                } else if (paramName.equalsIgnoreCase("domain")) {
                    cookie.setDomain(paramValue);
                } else if (paramName.equalsIgnoreCase("path")) {
                    cookie.setPath(paramValue);
                } else if (paramName.equalsIgnoreCase("comment")) {
                    cookie.setComment(paramValue);
                } else {
                    throw new AuthClientException("Invalid cookie: invalid attribute name for Cookie :" + rawCookie
                            + " . Accepted attributes are {expires, max-age, domain, path, comment} ");
                }
            }
        }

        return cookie;
    }
}
