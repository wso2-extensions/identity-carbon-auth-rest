package org.wso2.carbon.identity.auth.service;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;

import static org.testng.Assert.*;

@PowerMockIgnore("org.apache.tomcat.*")
public class AuthenticationRequestBuilderFactoryTest extends PowerMockTestCase{

    @Mock
    private Request request;
    @Mock
    private Response response;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetInstance() throws Exception {
        AuthenticationRequestBuilderFactory instance1 = AuthenticationRequestBuilderFactory.getInstance();
        AuthenticationRequestBuilderFactory instance2 = AuthenticationRequestBuilderFactory.getInstance();
        Assert.assertNotNull(instance1);
        Assert.assertNotNull(instance2);
        Assert.assertEquals(instance1, instance2);
    }

    @Test
    public void testCreateRequestBuilder() throws Exception {
        AuthenticationRequestBuilderFactory authenticationRequestBuilderFactory = AuthenticationRequestBuilderFactory.getInstance();
        authenticationRequestBuilderFactory.createRequestBuilder(request, response);
    }

    @Test
    public void testCanHandle() throws Exception {

    }

    @Test
    public void testGetPriority() throws Exception {

    }
}