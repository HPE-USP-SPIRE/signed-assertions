# OKTA Tutorial
The available PoC scenarios uses an OKTA OAuth token to identify an end-user behind a request. This tutorial explains how to create an OKTA application to generate the necessary token and keys.

**1.** Access https://developer.okta.com/ and create a user account  
**2.** Log in using created account  
**3.** On the left menu, expand "Applications" and click on "Applications", then click on the "Create app integration" button  
**4.** On the Create app integration window, select the "OIDC OpenID Connect" option, select "Web application" and click next  
**5.** On the new window, in "General Settings" give a name to the application and check the "Implicit (Hybrid)" option  
**6.** In "Sign-in redirect URIs" insert the redirect URI in the format "http://<your_ip>:8080/callback"  
**7.** In "Assignment", select "Allow everyone in your organization to access"  
**8.** Click in Save  

After the execution of the previous steps, the Client ID and Client Secret are generated. This information, along with the dev ID (that can be found in the okta web address), should be inserted in the .cfg file inside each scenario directories.
