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

package org.wso2.carbon.identity.auth.service.handler;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.common.base.message.MessageContext;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class AbstractAuthenticationHandlerTest {

    private AbstractAuthenticationHandler abstractAuthenticationHandler;

    @BeforeTest
    public void setUp() {
        abstractAuthenticationHandler = new AbstractAuthenticationHandler() {

            @Override
            protected String getAuthorizationHeaderType() {
                return null;
            }

            @Override
            protected AuthenticationResult doAuthenticate(MessageContext messageContext)
                    throws AuthServerException, AuthClientException {
                return null;
            }

            @Override
            public String getName() {
                return null;
            }
        };
    }

    @Test
    public void testCanHandle() throws Exception {
        ImmutablePair<String, String> domainAndUser = abstractAuthenticationHandler
                .decodeDomainAndUserName("userName");
        assertEquals(domainAndUser.getLeft(), "userName");

        domainAndUser = abstractAuthenticationHandler.decodeDomainAndUserName("");
        assertEquals(domainAndUser.getLeft(), "");

        domainAndUser = abstractAuthenticationHandler.decodeDomainAndUserName(null);
        assertNull(domainAndUser.getLeft());

        domainAndUser = abstractAuthenticationHandler.decodeDomainAndUserName("domain/userName");
        assertEquals(domainAndUser.getLeft(), "userName");
        assertEquals(domainAndUser.getRight(), "domain");

    }

    public void testDecodeTenantDomainAndUserName() {

    }

    @Test
    public void testGetAuthorizationHeaderType() throws Exception {

    }

    @Test
    public void testDoAuthenticate() throws Exception {

    }

    @Test
    public void testPostAuthenticate() throws Exception {

    }

    @Test
    public void testSetRealmService() throws Exception {

    }

    @Test
    public void testGetRealmService() throws Exception {

    }

}