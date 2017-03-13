package org.wso2.carbon.identity.auth.service.module;

import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Key representing the resource config in the REST.
 */
public class ResourceConfigKey {

    private String contextPath;
    private String httpMethod;

    private Pattern compiledPattern;

    public static ResourceConfigKey generateKey(ResourceConfig resourceConfig) {
        return new ResourceConfigKey(resourceConfig.getContext(), resourceConfig.getHttpMethod());
    }

    public ResourceConfigKey(String contextPath, String httpMethod) {
        this.contextPath = contextPath;
        this.httpMethod = httpMethod;
    }

    public String getContextPath() {
        return contextPath;
    }

    public String getHttpMethod() {
        return httpMethod;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ResourceConfigKey that = (ResourceConfigKey) o;
        Matcher matcher = getMatcher(that);
        if (!matcher.matches()) {
            return false;
        }

        if (httpMethod.equalsIgnoreCase("all")) {
            return true;
        }
        return httpMethod.contains(that.httpMethod);

    }

    private Matcher getMatcher(ResourceConfigKey that) {
        if (compiledPattern == null) {
            compiledPattern = Pattern.compile(contextPath);
        }
        return compiledPattern.matcher(that.contextPath == null? "": that.contextPath);
    }

    @Override
    public int hashCode() {
        HashCodeBuilder hashCodeBuilder = new HashCodeBuilder(21, 13);
        hashCodeBuilder.append(contextPath);
        hashCodeBuilder.append(httpMethod);

        return hashCodeBuilder.build();
    }
}
