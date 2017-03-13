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

package org.wso2.carbon.identity.auth.test.module.commons.utills;

import org.ops4j.pax.exam.Option;
import org.wso2.carbon.osgi.test.util.CarbonSysPropConfiguration;
import org.wso2.carbon.osgi.test.util.OSGiTestConfigurationUtils;

import java.util.ArrayList;
import java.util.List;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.systemProperty;
import static org.ops4j.pax.exam.CoreOptions.vmOption;

/**
 * This class contains the utility methods for  REST tests.
 */
public class AuthRestTestUtils {


    /**
     * Returns the default list of PAX options needed for  REST test.
     *
     * @return list of Options
     */
    public static List<Option> getDefaultSecurityPAXOptions() {

        List<Option> defaultOptionList = new ArrayList<>();


        defaultOptionList.add(mavenBundle()
                .groupId("org.ops4j.pax.logging")
                .artifactId("pax-logging-log4j2")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.ops4j.pax.logging")
                .artifactId("pax-logging-api")
                .versionAsInProject());

        defaultOptionList.add(mavenBundle().
                artifactId("testng").
                groupId("org.testng").versionAsInProject());

        defaultOptionList.add(mavenBundle()
                .groupId("net.minidev.wso2")
                .artifactId("json-smart")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("commons-io.wso2")
                .artifactId("commons-io")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("commons-pool.wso2").
                artifactId("commons-pool").versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.apache.commons")
                .artifactId("commons-lang3")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("net.minidev.wso2")
                .artifactId("json-smart")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("net.minidev")
                .artifactId("asm")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon")
                .artifactId("org.wso2.carbon.core")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.messaging")
                .artifactId("org.wso2.carbon.messaging")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.caching")
                .artifactId("org.wso2.carbon.caching")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.identity.mgt")
                .artifactId("org.wso2.carbon.identity.mgt")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.identity.mgt")
                .artifactId("org.wso2.carbon.identity.claim")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.identity.mgt")
                .artifactId("in-memory-connectors-test-artifact")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.identity.commons")
                .artifactId("org.wso2.carbon.identity.event")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.datasources")
                .artifactId("org.wso2.carbon.datasource.core")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.jndi")
                .artifactId("org.wso2.carbon.jndi")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("com.zaxxer")
                .artifactId("HikariCP")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("com.h2database")
                .artifactId("h2")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.identity.commons")
                .artifactId("org.wso2.carbon.identity.commons")
                .versionAsInProject());

        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.msf4j")
                .artifactId("msf4j-core")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("org.wso2.carbon.transport").
                artifactId("org.wso2.carbon.transport.http.netty")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-transport").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-buffer").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-common").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-codec").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-codec-http").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("io.netty").
                artifactId("netty-handler").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("javax.ws.rs").
                artifactId("javax.ws.rs-api").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("com.google.code.gson").
                artifactId("gson").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("org.apache.servicemix.bundles").
                artifactId("org.apache.servicemix.bundles.commons-beanutils")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("org.wso2.orbit.com.lmax").
                artifactId("disruptor").versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("io.swagger").
                artifactId("swagger-annotations")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("org.wso2.msf4j").
                artifactId("jaxrs-delegates")
                .versionAsInProject().noStart());

        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.lcm")
                .artifactId("org.wso2.carbon.lcm.core")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle()
                .groupId("org.wso2.carbon.lcm")
                .artifactId("org.wso2.carbon.lcm.sql")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("org.wso2.carbon.identity.auth.rest").
                artifactId("identity-auth-rest-test-service")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("org.wso2.carbon.identity.auth.rest").
                artifactId("org.wso2.carbon.identity.auth.msf4j.interceptor")
                .versionAsInProject());
        defaultOptionList.add(mavenBundle().
                groupId("org.wso2.carbon.identity.auth.rest").
                artifactId("org.wso2.carbon.identity.auth.service")
                .versionAsInProject());
        defaultOptionList.add(systemProperty("osgi.console").value("6666"));
        defaultOptionList.add(systemProperty("org.ops4j.pax.logging.DefaultServiceLog.level").value("DEBUG"));


        CarbonSysPropConfiguration sysPropConfiguration = new CarbonSysPropConfiguration();
        sysPropConfiguration.setCarbonHome(getCarbonHome());
        sysPropConfiguration.setServerKey("carbon-security");
        sysPropConfiguration.setServerName("WSO2 Carbon Security Server");
        sysPropConfiguration.setServerVersion("1.0.0");


        defaultOptionList = OSGiTestConfigurationUtils.getConfiguration(defaultOptionList, sysPropConfiguration);

        return defaultOptionList;
    }

    public static String getCarbonHome() {
        return System.getProperty("carbon.home");
    }
}

