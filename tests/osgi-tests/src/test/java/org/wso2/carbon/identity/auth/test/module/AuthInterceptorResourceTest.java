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

package org.wso2.carbon.identity.auth.test.module;

import org.apache.commons.io.Charsets;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.test.module.commons.utills.AuthRestTestUtils;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;

import static org.testng.Assert.assertEquals;

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class AuthInterceptorResourceTest {

    private URI baseURI = URI.create(String.format("http://%s:%d", "localhost", 8080));
    private static final String SERVICE_PATH = "/simple-rest/test/hello/me";

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;

    @Inject
    private AuthenticationManager authenticationManager;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = AuthRestTestUtils.getDefaultSecurityPAXOptions();

        return optionList.toArray(new Option[optionList.size()]);
    }

    @Test(description = "Checking authentication with BASIC")
    public void testBasicAuthInterceptor() throws Exception {
        callWithBasicAuthSuccess("ok_user:ok_user");
        callWithBasicAuthSuccess_WithCookies("ok_user:ok_user");
        callWithBasicAuthFail("ok_user:bad_pass", 401, "Wrong password in Basic Authentication should result in 401");
        callWithBasicAuthSuccess("domain1/ok_user:ok_user");
        callWithBasicAuthFail("ok_user", 400, "Incorrect Basic Authentication should result in HTTP Bad Request");
        callWithBasicAuthFail("IdentityStoreException:bad", 500, "Should fail when Identity Store exception occurs");
        callWithBasicAuthFailWrongFormat("ok_user:ok_user", 500, "Wrong format should fail");
    }

    @Test(description = "Checking authentication with BASIC with debug log enabled")
    public void testBasicAuthInterceptorWithDebug() throws Exception {
        System.setProperty("org.ops4j.pax.logging.DefaultServiceLog.level", "DEBUG");
        testBasicAuthInterceptor();
    }

    protected void callWithBasicAuthSuccess(String userCredentials) throws IOException {
        HttpURLConnection urlConn = request(SERVICE_PATH, HttpMethod.GET, false);
        attachBasicAuthHeader(urlConn, userCredentials);

        assertEquals(urlConn.getResponseCode(), 200, "Successful Basic Authentication should proceed");
    }

    protected void callWithBasicAuthSuccess_WithCookies(String userCredentials) throws IOException {
        HttpURLConnection urlConn = request(SERVICE_PATH, HttpMethod.GET, true);
        attachBasicAuthHeader(urlConn, userCredentials);

        assertEquals(urlConn.getResponseCode(), 200, "Successful Basic Authentication should proceed");
    }

    protected void callWithBasicAuthFail(String userCredentials, int expected, String reason) throws IOException {
        HttpURLConnection urlConn = request(SERVICE_PATH, HttpMethod.GET, false);
        attachBasicAuthHeader(urlConn, userCredentials);

        assertEquals(urlConn.getResponseCode(), expected, reason);
    }

    protected void callWithBasicAuthFailWrongFormat(String userCredentials, int expected, String reason) throws IOException {
        HttpURLConnection urlConn = request(SERVICE_PATH, HttpMethod.GET, false);
        attachBasicAuthHeaderWithWrongFormat(urlConn, userCredentials);

        assertEquals(urlConn.getResponseCode(), expected, reason);
    }

    private void attachBasicAuthHeader(HttpURLConnection urlConn, String userCredentials) {
        String basicAuth =
                "Basic " + new String(Base64.getEncoder().encode(userCredentials.getBytes(Charsets.ISO_8859_1)));
        basicAuth = basicAuth.replaceAll("\n", "");
        urlConn.setRequestProperty("Authorization", basicAuth);
    }

    /**
     * This will attach the wrong basic auth header. i.e. No space separating the type and credentials
     * Basic12345.
     * @param urlConn
     * @param userCredentials
     */
    private void attachBasicAuthHeaderWithWrongFormat(HttpURLConnection urlConn, String userCredentials) {
        String basicAuth =
                "Basic" + new String(Base64.getEncoder().encode(userCredentials.getBytes(Charsets.ISO_8859_1)));
        basicAuth = basicAuth.replaceAll("\n", "");
        urlConn.setRequestProperty("Authorization", basicAuth);
    }

    protected HttpURLConnection request(String path, String method, boolean isWithCookies)
            throws IOException {
        java.net.URL url = baseURI.resolve(path).toURL();
        HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
        if (method.equals(HttpMethod.POST) || method.equals(HttpMethod.PUT)) {
            urlConn.setDoOutput(true);
        }
        urlConn.setRequestMethod(method);

        if (isWithCookies) {
            // Set the cookie values to send
            urlConn.setRequestProperty("Cookie", "name1=value1; name2=value2");
        }

        return urlConn;
    }
}
