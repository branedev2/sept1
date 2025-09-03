import com.amazonaws.auth.policy.Policy;
import com.amazonaws.auth.policy.Statement;
import com.amazonaws.auth.policy.Principal;
import com.amazonaws.auth.policy.actions.S3Actions;
import com.amazonaws.auth.policy.Resource;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.BucketPolicy;
import com.google.cloud.iam.v1.Binding;
import com.google.cloud.iam.v1.Policy.Builder;
import com.google.cloud.iam.v1.SetIamPolicyRequest;
import com.google.iam.v1.TestIamPermissionsRequest;
import com.google.iam.v1.TestIamPermissionsResponse;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.storage.models.StorageAccount;
import com.azure.resourcemanager.authorization.models.RoleAssignment;
import com.azure.resourcemanager.authorization.models.RoleDefinition;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.CreatePolicyRequest;
import software.amazon.awssdk.services.iam.model.CreatePolicyResponse;
import software.amazon.awssdk.services.iam.model.PutRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.PutRolePolicyResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.apis.RbacAuthorizationV1Api;
import io.kubernetes.client.openapi.models.V1Role;
import io.kubernetes.client.openapi.models.V1RoleBinding;
import io.kubernetes.client.openapi.models.V1Subject;
import io.kubernetes.client.util.ClientBuilder;
import com.oracle.bmc.auth.AuthenticationDetailsProvider;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.identity.IdentityClient;
import com.oracle.bmc.identity.model.CreatePolicyDetails;
import com.oracle.bmc.identity.requests.CreatePolicyRequest;
import com.oracle.bmc.identity.responses.CreatePolicyResponse;
import com.digitalocean.api.client.DigitalOceanClient;
import com.digitalocean.api.client.generated.ProjectsApi;
import com.digitalocean.api.models.Project;
import com.digitalocean.api.models.ProjectBase;
import com.linode.api.ApiClient;
import com.linode.api.Configuration;
import com.linode.api.auth.ApiKeyAuth;
import com.linode.api.v4.UsersApi;
import com.linode.api.v4.model.GrantsResponse;
import com.linode.api.v4.model.UserCreateOptions;
import com.linode.api.v4.model.UserResponse;
import com.ibm.cloud.sdk.core.security.IamAuthenticator;
import com.ibm.cloud.sdk.core.service.exception.ServiceResponseException;
import com.ibm.cloud.sdk.core.service.model.GenericModel;
import com.ibm.cloud.iamaccessgroups.v2.IamAccessGroups;
import com.ibm.cloud.iamaccessgroups.v2.model.AccessGroupResponse;
import com.ibm.cloud.iamaccessgroups.v2.model.CreateAccessGroupOptions;
import com.ibm.cloud.iamaccessgroups.v2.model.CreateAccessGroupResponse;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.RoleRepresentation;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import org.json.JSONObject;
import org.json.JSONArray;

// Security Issue: Manually creating IAM policies through string manipulation is highly error-prone and can lead to unintended access permissions

// True Positive Examples (Vulnerable/Insecure Code)
public class HandcraftedIAMPolicies {

// {fact rule=aws-iam-error-prone-policy@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String userName = request.getParameter("userName");
        String resourceArn = request.getParameter("resourceArn");
        
        // Create AWS IAM policy using string concatenation
        // ruleid: java-handcrafted-policies
        String policyDocument = "{\"Version\": \"2012-10-17\", \"Statement\": [{" +
                "\"Effect\": \"Allow\"," +
                "\"Principal\": {\"AWS\": \"" + userName + "\"}," +
                "\"Action\": \"s3:*\"," +
                "\"Resource\": \"" + resourceArn + "\"" +
                "}]}";
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        s3Client.setBucketPolicy("my-bucket", new BucketPolicy().withPolicyText(policyDocument));
    }
    
    public void bad_case_2(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String actionName = request.getParameter("actionName");
        
        // Create AWS IAM policy using string manipulation with AWS SDK v2
        // ruleid: java-handcrafted-policies
        String policyJson = String.format(
            "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"%s\"],\"Resource\":\"*\"}]}",
            actionName
        );
        
        IamClient iamClient = IamClient.builder().build();
        PutRolePolicyRequest putRolePolicyRequest = PutRolePolicyRequest.builder()
            .roleName(roleName)
            .policyName("DynamicPolicy")
            .policyDocument(policyJson)
            .build();
        
        PutRolePolicyResponse response = iamClient.putRolePolicy(putRolePolicyRequest);
    }
    
    public void bad_case_3(HttpServletRequest request) {
        String projectId = request.getParameter("projectId");
        String member = request.getParameter("member");
        
        // Create GCP IAM policy using string manipulation
        // ruleid: java-handcrafted-policies
        String policyJson = "{\n" +
            "  \"bindings\": [\n" +
            "    {\n" +
            "      \"role\": \"roles/storage.objectAdmin\",\n" +
            "      \"members\": [\"" + member + "\"]\n" +
            "    }\n" +
            "  ]\n" +
            "}";
        
        // This would typically be used with a GCP API client
        System.out.println("Setting policy for project " + projectId + ": " + policyJson);
    }
    
    public void bad_case_4(HttpServletRequest request) {
        String principalId = request.getParameter("principalId");
        String resourceId = request.getParameter("resourceId");
        
        // Create Azure role assignment using string manipulation
        // ruleid: java-handcrafted-policies
        String roleDefinitionJson = "{\n" +
            "  \"properties\": {\n" +
            "    \"roleName\": \"Custom Role\",\n" +
            "    \"description\": \"Custom role created via API\",\n" +
            "    \"assignableScopes\": [\"/subscriptions/00000000-0000-0000-0000-000000000000\"],\n" +
            "    \"permissions\": [\n" +
            "      {\n" +
            "        \"actions\": [\"Microsoft.Storage/storageAccounts/read\"],\n" +
            "        \"notActions\": [],\n" +
            "        \"dataActions\": [],\n" +
            "        \"notDataActions\": []\n" +
            "      }\n" +
            "    ]\n" +
            "  }\n" +
            "}";
        
        System.out.println("Creating role definition: " + roleDefinitionJson);
    }
    
    public void bad_case_5(HttpServletRequest request) {
        String namespace = request.getParameter("namespace");
        String username = request.getParameter("username");
        
        // Create Kubernetes RBAC_REDACTED_TWILIO_ID policy using string manipulation
        // ruleid: java-handcrafted-policies
        String roleBindingYaml = "apiVersion: rbac.authorization.k8s.io/v1\n" +
            "kind: RoleBinding\n" +
            "metadata:\n" +
            "  name: pod-reader-binding\n" +
            "  namespace: " + namespace + "\n" +
            "subjects:\n" +
            "- kind: User\n" +
            "  name: " + username + "\n" +
            "  apiGroup: rbac.authorization.k8s.io\n" +
            "roleRef:\n" +
            "  kind: Role\n" +
            "  name: pod-reader\n" +
            "  apiGroup: rbac.authorization.k8s.io";
        
        System.out.println("Creating role binding: " + roleBindingYaml);
    }
    
    public void bad_case_6(HttpServletRequest request) {
        String compartmentId = request.getParameter("compartmentId");
        String policyName = request.getParameter("policyName");
        String groupName = request.getParameter("groupName");
        
        // Create Oracle Cloud Infrastructure policy using string manipulation
        // ruleid: java-handcrafted-policies
        String policyStatement = "Allow group " + groupName + " to manage all-resources in compartment " + compartmentId;
        String policyJson = "{\n" +
            "  \"compartmentId\": \"" + compartmentId + "\",\n" +
            "  \"name\": \"" + policyName + "\",\n" +
            "  \"statements\": [\"" + policyStatement + "\"],\n" +
            "  \"description\": \"Policy created via API\"\n" +
            "}";
        
        System.out.println("Creating OCI policy: " + policyJson);
    }
    
    public void bad_case_7(HttpServletRequest request) {
        String projectId = request.getParameter("projectId");
        String projectName = request.getParameter("projectName");
        
        // Create DigitalOcean project with permissions using string manipulation
        // ruleid: java-handcrafted-policies
        String projectJson = "{\n" +
            "  \"name\": \"" + projectName + "\",\n" +
            "  \"description\": \"Project created via API\",\n" +
            "  \"purpose\": \"Web Application\",\n" +
            "  \"environment\": \"Production\",\n" +
            "  \"resources\": [\"do:droplet:" + projectId + "\"]\n" +
            "}";
        
        System.out.println("Creating DigitalOcean project: " + projectJson);
    }
    
    public void bad_case_8(HttpServletRequest request) {
        String username = request.getParameter("username");
        String permission = request.getParameter("permission");
        
        // Create Linode user grants using string manipulation
        // ruleid: java-handcrafted-policies
        String grantsJson = "{\n" +
            "  \"global\": {\n" +
            "    \"account_access\": \"read_only\",\n" +
            "    \"" + permission + "\": true\n" +
            "  },\n" +
            "  \"linode\": [\n" +
            "    {\n" +
            "      \"id\": 123,\n" +
            "      \"permissions\": \"read_write\"\n" +
            "    }\n" +
            "  ]\n" +
            "}";
        
        System.out.println("Creating grants for user " + username + ": " + grantsJson);
    }
    
    public void bad_case_9(HttpServletRequest request) {
        String accessGroupName = request.getParameter("accessGroupName");
        String accountId = request.getParameter("accountId");
        
        // Create IBM Cloud IAM access group using string manipulation
        // ruleid: java-handcrafted-policies
        String accessGroupJson = "{\n" +
            "  \"name\": \"" + accessGroupName + "\",\n" +
            "  \"description\": \"Access group created via API\",\n" +
            "  \"account_id\": \"" + accountId + "\"\n" +
            "}";
        
        System.out.println("Creating IBM Cloud access group: " + accessGroupJson);
    }
    
    public void bad_case_10(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String permission = request.getParameter("permission");
        
        // Create Apache Shiro permissions using string manipulation
        // ruleid: java-handcrafted-policies
        String iniConfig = "[users]\n" +
            "admin = password, admin\n" +
            "user1 = password, user\n" +
            "\n" +
            "[roles]\n" +
            "admin = *\n" +
            "user = " + permission + ":read,write";
        
        System.out.println("Creating Shiro configuration: " + iniConfig);
    }
    
    public void bad_case_11(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String resourceName = request.getParameter("resourceName");
        
        // Create Keycloak role with permissions using string manipulation
        // ruleid: java-handcrafted-policies
        String roleJson = "{\n" +
            "  \"name\": \"" + roleName + "\",\n" +
            "  \"description\": \"Role created via API\",\n" +
            "  \"composite\": false,\n" +
            "  \"clientRole\": false,\n" +
            "  \"attributes\": {\n" +
            "    \"permissions\": [\"" + resourceName + ":read\", \"" + resourceName + ":write\"]\n" +
            "  }\n" +
            "}";
        
        System.out.println("Creating Keycloak role: " + roleJson);
    }
    
    public void bad_case_12(HttpServletRequest request) {
        String username = request.getParameter("username");
        String resource = request.getParameter("resource");
        
        // Create Spring Security expression using string manipulation
        // ruleid: java-handcrafted-policies
        String securityExpression = "hasRole('ADMIN') or hasPermission('" + resource + "', 'read') or principal.username == '" + username + "'";
        
        System.out.println("Using security expression: " + securityExpression);
        // This would typically be used in a @PreAuthorize annotation
    }
    
    public void bad_case_13(HttpServletRequest request) {
        String policyName = request.getParameter("policyName");
        String actionPattern = request.getParameter("actionPattern");
        
        // Create AWS IAM policy document using JSON manipulation
        JSONObject statement = new JSONObject();
        statement.put("Effect", "Allow");
        JSONArray actions = new JSONArray();
        
        // ruleid: java-handcrafted-policies
        actions.put(actionPattern + ":*");
        statement.put("Action", actions);
        statement.put("Resource", "*");
        
        JSONArray statementArray = new JSONArray();
        statementArray.put(statement);
        
        JSONObject policyDocument = new JSONObject();
        policyDocument.put("Version", "2012-10-17");
        policyDocument.put("Statement", statementArray);
        
        IamClient iamClient = IamClient.builder().build();
        CreatePolicyRequest createPolicyRequest = CreatePolicyRequest.builder()
            .policyName(policyName)
            .policyDocument(policyDocument.toString())
            .build();
        
        CreatePolicyResponse response = iamClient.createPolicy(createPolicyRequest);
    }
    
    public void bad_case_14(HttpServletRequest request) {
        String principal = request.getParameter("principal");
        String action = request.getParameter("action");
        
        // Create AWS S3 bucket policy using StringBuilder
        StringBuilder policyBuilder = new StringBuilder();
        policyBuilder.append("{\"Version\":\"2012-10-17\",\"Statement\":[{");
        policyBuilder.append("\"Effect\":\"Allow\",");
        
        // ruleid: java-handcrafted-policies
        policyBuilder.append("\"Principal\":{\"AWS\":\"").append(principal).append("\"},");
        policyBuilder.append("\"Action\":\"").append(action).append("\",");
        policyBuilder.append("\"Resource\":\"arn:aws:s3:::example-bucket/*\"");
        policyBuilder.append("}]}");
        
        String policyDocument = policyBuilder.toString();
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        s3Client.setBucketPolicy("example-bucket", new BucketPolicy().withPolicyText(policyDocument));
    }
    
    public void bad_case_15(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String serviceAccount = request.getParameter("serviceAccount");
        
        // Create GCP IAM policy using string formatting
        // ruleid: java-handcrafted-policies
        String policyTemplate = 
            "{" +
            "  \"bindings\": [" +
            "    {" +
            "      \"role\": \"roles/%s\"," +
            "      \"members\": [" +
            "        \"serviceAccount:%s\"" +
            "      ]" +
            "    }" +
            "  ]" +
            "}";
        
        String policyJson = String.format(policyTemplate, roleName, serviceAccount);
        
        System.out.println("Creating GCP IAM policy: " + policyJson);
    }
    
    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) {
        String userName = request.getParameter("userName");
        String resourceArn = request.getParameter("resourceArn");
        
        // Create AWS IAM policy using the AWS SDK Policy objects
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        policy.withStatements(new Statement(Statement.Effect.Allow)
            .withPrincipals(new Principal("AWS", userName))
            .withActions(S3Actions.GetObject)
            .withResources(new Resource(resourceArn)));
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        s3Client.setBucketPolicy("my-bucket", new BucketPolicy().withPolicyText(policy.toJson()));
    }
    
    public void good_case_2(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String actionName = request.getParameter("actionName");
        
        // Create AWS IAM policy using AWS SDK v2 policy builder
        // ok: java-handcrafted-policies
        IamClient iamClient = IamClient.builder().build();
        
        Map<String, String> policyDocument = new HashMap<>();
        Map<String, Object> statement = new HashMap<>();
        statement.put("Effect", "Allow");
        statement.put("Action", Arrays.asList(actionName));
        statement.put("Resource", "*");
        
        policyDocument.put("Version", "2012-10-17");
        policyDocument.put("Statement", Collections.singletonList(statement));
        
        PutRolePolicyRequest putRolePolicyRequest = PutRolePolicyRequest.builder()
            .roleName(roleName)
            .policyName("DynamicPolicy")
            .policyDocument(new JSONObject(policyDocument).toString())
            .build();
        
        PutRolePolicyResponse response = iamClient.putRolePolicy(putRolePolicyRequest);
    }
    
    public void good_case_3(HttpServletRequest request) {
        String projectId = request.getParameter("projectId");
        String member = request.getParameter("member");
        
        // Create GCP IAM policy using the GCP SDK Policy builder
        // ok: java-handcrafted-policies
        com.google.cloud.iam.v1.Policy.Builder policyBuilder = com.google.cloud.iam.v1.Policy.newBuilder();
        
        Binding binding = Binding.newBuilder()
            .setRole("roles/storage.objectAdmin")
            .addMembers(member)
            .build();
        
        policyBuilder.addBindings(binding);
        
        SetIamPolicyRequest setIamPolicyRequest = SetIamPolicyRequest.newBuilder()
            .setPolicy(policyBuilder.build())
            .build();
        
        System.out.println("Setting policy for project " + projectId + " using proper builder");
    }
    
    public void good_case_4(HttpServletRequest request) {
        String principalId = request.getParameter("principalId");
        String resourceId = request.getParameter("resourceId");
        
        // Create Azure role assignment using the Azure SDK
        // ok: java-handcrafted-policies
        AzureResourceManager azureResourceManager = AzureResourceManager.authenticate(null, null)
            .withDefaultSubscription();
        
        RoleDefinition roleDefinition = azureResourceManager.accessManagement().roleDefinitions()
            .getByScopeAndRoleName("subscriptions/subId", "Contributor");
        
        RoleAssignment roleAssignment = azureResourceManager.accessManagement().roleAssignments()
            .define(java.util.UUID.randomUUID().toString())
            .forObjectId(principalId)
            .withRoleDefinition(roleDefinition.id())
            .withScope(resourceId)
            .create();
        
        System.out.println("Role assignment created with ID: " + roleAssignment.id());
    }
    
    public void good_case_5(HttpServletRequest request) {
        String namespace = request.getParameter("namespace");
        String username = request.getParameter("username");
        
        // Create Kubernetes RBAC_REDACTED_TWILIO_ID policy using the Kubernetes Java client
        try {
            // ok: java-handcrafted-policies
            ApiClient client = ClientBuilder.standard().build();
            RbacAuthorizationV1Api rbacApi = new RbacAuthorizationV1Api(client);
            
            V1RoleBinding roleBinding = new V1RoleBinding()
                .metadata(new io.kubernetes.client.openapi.models.V1ObjectMeta().name("pod-reader-binding").namespace(namespace))
                .subjects(Collections.singletonList(
                    new V1Subject().kind("User").name(username).apiGroup("rbac.authorization.k8s.io")
                ))
                .roleRef(new io.kubernetes.client.openapi.models.V1RoleRef()
                    .kind("Role")
                    .name("pod-reader")
                    .apiGroup("rbac.authorization.k8s.io"));
            
            rbacApi.createNamespacedRoleBinding(namespace, roleBinding, null, null, null, null);
            System.out.println("Created role binding in namespace " + namespace);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6(HttpServletRequest request) {
        String compartmentId = request.getParameter("compartmentId");
        String policyName = request.getParameter("policyName");
        String groupName = request.getParameter("groupName");
        
        try {
            // Create Oracle Cloud Infrastructure policy using the OCI SDK
            // ok: java-handcrafted-policies
            AuthenticationDetailsProvider provider = new ConfigFileAuthenticationDetailsProvider("~/.oci/config", "DEFAULT");
            IdentityClient identityClient = IdentityClient.builder().build(provider);
            
            CreatePolicyDetails createPolicyDetails = CreatePolicyDetails.builder()
                .compartmentId(compartmentId)
                .name(policyName)
                .statements(Collections.singletonList("Allow group " + groupName + " to manage all-resources in compartment id " + compartmentId))
                .description("Policy created via API")
                .build();
            
            com.oracle.bmc.identity.requests.CreatePolicyRequest createPolicyRequest = 
                com.oracle.bmc.identity.requests.CreatePolicyRequest.builder()
                    .createPolicyDetails(createPolicyDetails)
                    .build();
            
            CreatePolicyResponse response = identityClient.createPolicy(createPolicyRequest);
            System.out.println("Created policy with ID: " + response.getPolicy().getId());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7(HttpServletRequest request) {
        String projectId = request.getParameter("projectId");
        String projectName = request.getParameter("projectName");
        
        // Create DigitalOcean project with permissions using the DigitalOcean SDK
        // ok: java-handcrafted-policies
        DigitalOceanClient client = new DigitalOceanClient("api-token");
        ProjectsApi projectsApi = client.projects();
        
        ProjectBase projectBase = new ProjectBase()
            .setName(projectName)
            .setDescription("Project created via API")
            .setPurpose("Web Application")
            .setEnvironment(ProjectBase.Environment.PRODUCTION);
        
        Project project = projectsApi.create(projectBase);
        System.out.println("Created project with ID: " + project.getId());
    }
    
    public void good_case_8(HttpServletRequest request) {
        String username = request.getParameter("username");
        String permission = request.getParameter("permission");
        
        // Create Linode user grants using the Linode Java SDK
        // ok: java-handcrafted-policies
        ApiClient apiClient = Configuration.getDefaultApiClient();
        ApiKeyAuth apiKeyAuth = (ApiKeyAuth) apiClient.getAuthentication("personalAccessToken");
        apiKeyAuth.setApiKey("your-api-key");
        
        UsersApi usersApi = new UsersApi(apiClient);
        UserCreateOptions userCreateOptions = new UserCreateOptions()
            .username(username)
            .email("user@example.com")
            .restricted(true);
        
        UserResponse userResponse = usersApi.createUser(userCreateOptions);
        System.out.println("Created user with ID: " + userResponse.getId());
    }
    
    public void good_case_9(HttpServletRequest request) {
        String accessGroupName = request.getParameter("accessGroupName");
        String accountId = request.getParameter("accountId");
        
        // Create IBM Cloud IAM access group using the IBM Cloud SDK
        // ok: java-handcrafted-policies
        IamAuthenticator authenticator = new IamAuthenticator.Builder()
            .apikey("your-api-key")
            .build();
        
        IamAccessGroups accessGroupsService = new IamAccessGroups(authenticator);
        accessGroupsService.setServiceUrl("https://iam.cloud.ibm.com");
        
        CreateAccessGroupOptions createAccessGroupOptions = new CreateAccessGroupOptions.Builder()
            .accountId(accountId)
            .name(accessGroupName)
            .description("Access group created via API")
            .build();
        
        CreateAccessGroupResponse response = accessGroupsService.createAccessGroup(createAccessGroupOptions).execute().getResult();
        System.out.println("Created access group with ID: " + response.getId());
    }
    
    public void good_case_10(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String permission = request.getParameter("permission");
        
        // Create Apache Shiro permissions using the Shiro API
        // ok: java-handcrafted-policies
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        
        SimpleRole role = new SimpleRole(roleName);
        Permission perm = new WildcardPermission(permission);
        role.add(perm);
        
        System.out.println("Created role with permission: " + permission);
    }
    
    public void good_case_11(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String resourceName = request.getParameter("resourceName");
        
        // Create Keycloak role with permissions using the Keycloak Admin Client
        // ok: java-handcrafted-policies
        Keycloak keycloak = KeycloakBuilder.builder()
            .serverUrl("https://keycloak.example.com/auth")
            .realm("master")
            .username("admin")
            .password("password")
            .clientId("admin-cli")
            .build();
        
        RealmResource realmResource = keycloak.realm("myrealm");
        RolesResource rolesResource = realmResource.roles();
        
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        role.setDescription("Role created via API");
        
        rolesResource.create(role);
        System.out.println("Created Keycloak role: " + roleName);
    }
    
    public void good_case_12(HttpServletRequest request) {
        String username = request.getParameter("username");
        String resource = request.getParameter("resource");
        
        // Use Spring Security's built-in annotations for authorization
        // ok: java-handcrafted-policies
        @EnableGlobalMethodSecurity(prePostEnabled = true)
        class SecurityConfig extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                http
                    .authorizeRequests()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                    .anyRequest().authenticated();
            }
        }
        
        // Method with proper authorization annotation
        @PreAuthorize("hasRole('ADMIN') or hasPermission(#resource, 'read') or principal.username == #username")
        public void secureMethod(String resource, String username) {
            System.out.println("Accessing resource: " + resource);
        }
    }
    
    public void good_case_13(HttpServletRequest request) {
        String policyName = request.getParameter("policyName");
        String actionPattern = request.getParameter("actionPattern");
        
        // Create AWS IAM policy using the AWS SDK policy objects
        // ok: java-handcrafted-policies
        IamClient iamClient = IamClient.builder().build();
        
        Map<String, Object> policyDocument = new HashMap<>();
        policyDocument.put("Version", "2012-10-17");
        
        List<Map<String, Object>> statements = new ArrayList<>();
        Map<String, Object> statement = new HashMap<>();
        statement.put("Effect", "Allow");
        statement.put("Action", Arrays.asList(actionPattern + ":List", actionPattern + ":Get"));
        statement.put("Resource", "*");
        statements.add(statement);
        
        policyDocument.put("Statement", statements);
        
        CreatePolicyRequest createPolicyRequest = CreatePolicyRequest.builder()
            .policyName(policyName)
            .policyDocument(new JSONObject(policyDocument).toString())
            .build();
        
        CreatePolicyResponse response = iamClient.createPolicy(createPolicyRequest);
    }
    
    public void good_case_14(HttpServletRequest request) {
        String principal = request.getParameter("principal");
        String action = request.getParameter("action");
        
        // Create AWS S3 bucket policy using the AWS SDK Policy objects
        // ok: java-handcrafted-policies
        Policy policy = new Policy();
        Statement statement = new Statement(Statement.Effect.Allow)
            .withPrincipals(new Principal("AWS", principal));
        
        if ("s3:GetObject".equals(action)) {
            statement.withActions(S3Actions.GetObject);
        } else if ("s3:PutObject".equals(action)) {
            statement.withActions(S3Actions.PutObject);
        } else {
            statement.withActions(S3Actions.ListBucket);
        }
        
        statement.withResources(new Resource("arn:aws:s3:::example-bucket/*"));
        policy.withStatements(statement);
        
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        s3Client.setBucketPolicy("example-bucket", new BucketPolicy().withPolicyText(policy.toJson()));
    }
    
    public void good_case_15(HttpServletRequest request) {
        String roleName = request.getParameter("roleName");
        String serviceAccount = request.getParameter("serviceAccount");
        
        // Create GCP IAM policy using the GCP SDK
        // ok: java-handcrafted-policies
        com.google.cloud.iam.v1.Policy.Builder policyBuilder = com.google.cloud.iam.v1.Policy.newBuilder();
        
        Binding.Builder bindingBuilder = Binding.newBuilder()
            .setRole("roles/" + roleName);
        
        bindingBuilder.addMembers("serviceAccount:" + serviceAccount);
        policyBuilder.addBindings(bindingBuilder.build());
        
        com.google.cloud.iam.v1.Policy policy = policyBuilder.build();
        System.out.println("Created GCP IAM policy using proper builder");
    }
}
// {/fact}