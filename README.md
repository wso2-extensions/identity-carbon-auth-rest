#identity-carbon-auth-rest

## Custom Header Filter
Custom Header Filter to add customer headers for applications using the resource manager service. 

### Setting-up Guide
1. Setup WSO2 Identity Server and enable **Configuration Manager**
   
   https://is.docs.wso2.com/en/latest/develop/using-the-configuration-management-rest-apis/
  
2. Build the project and copy `org.wso2.carbon.identity.custom.header.filter-${project.version}.jar` to the
   `<IS_HOME>/repository/components/dropins` directory.

3. Open `web.xml` (`web.xml.j2`) and enable the CustomHeaderFilter by adding following lines
   ```
       <filter>
           <filter-name>CustomHeaderFilter</filter-name>
           <filter-class>CustomHeaderFilter</filter-class>
       </filter>
   
       <filter-mapping>
           <filter-name>CustomHeaderFilter</filter-name>
           <url-pattern>/*</url-pattern>
           <dispatcher>REQUEST</dispatcher>
           <dispatcher>FORWARD</dispatcher>
       </filter-mapping>
   ```

4. Create custom header configurations through the **Configuration Manager API**.
