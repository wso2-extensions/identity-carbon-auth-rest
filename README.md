#identity-carbon-auth-rest

## Custom Header Filter
Custom Header Filter to add customer headers for applications using the resource manager service. 

### Setting-up Guide
1. Setup WSO2 Identity Server and enable **Configuration Manager**
   
   https://is.docs.wso2.com/en/latest/develop/using-the-configuration-management-rest-apis/
  
2. Build the project and copy `org.wso2.carbon.identity.custom.header.filter-${project.version}.jar` to the
   `<IS_HOME>/repository/components/dropins` directory.

3. Open `deployment.toml` and enable the CustomHeaderFilter by adding following lines
   ```
      [custom_header_filter]
      enable = true
   ```

4. Create custom header configurations through the **Configuration Manager API**.
