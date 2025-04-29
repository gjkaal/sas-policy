# Sas-Policy

A shared access policy token (sometimes called a shared access signature or SAS token) is considered an 
easy way to secure an API or other online resources because:

- **Simple to generate:**
  You just sign a URL or a request with a secret key and some rules (like expiry time, allowed permissions). 
  No complicated authentication flows are needed.
- **No user management:**
  You don't have to manage users, passwords, or OAuth flows — just distribute the signed token or signed URL. 
  Perfect for service-to-service scenarios.
- **Scoped access:**
  You can limit the token's permissions (read-only, write-only, etc.), resources (only a specific API or file), 
  and valid time window (e.g., valid for only 1 hour). If it leaks, the damage is controlled.

Validating a SAS token is straightforward as well. The server checks the token's signature, 
expiration time, and any other constraints (like permissions). If everything checks out, 
the request is allowed; otherwise, it's denied.

### Example in C#

Here’s an example that demonstrates how to generate a token and use it as as an authentication token in an HTTP request. 

``` csharp
using N2.Security.Sas; 
using System; 
using System.Net.Http; 
using System.Threading.Tasks;

class Program { 

    static async Task Main() { 
        // Step 1: Create a SAS Policy. 
    
        var policy = SASPolicyFactory.CreatePolicy( 
        skn: "mySigningKeyName", 
        sharedSecret: "mySharedSecret", 
        timeoutInSeconds: 300, // Token valid for 5 minutes 
        hashType: HashType.Sha256 );

        // Step 2: Use the policy to create a SAS Token
        var sharedResourceName = "https://myresource.com/resource";
        var token = SasTokenFactory.Create(
            sharedResourceName: sharedResourceName,
            policy: policy
        );

        // Step 3: Use the token in an HTTP request
        using var httpClient = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, sharedResourceName);

        // Add the token as a Bearer token in the Authorization header
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.Signature);

        
        // Step 3: Construct the token as a Base64-encoded string
        var tokenString = $"skn={token.SigningKeyName}"
            + "&sr={string.Join(",", token.SharedResource)}"
            + "&se={token.Expiry}"
            + "&sig={token.Signature}"
            + "&nonce={token.Nonce}";
        var base64EncodedToken = Convert.ToBase64String(Encoding.UTF8.GetBytes(tokenString));

        // Step 4: Use the Base64-encoded token in an HTTP request
        using var httpClient = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, sharedResourceName);
        var response = await httpClient.SendAsync(request);

        // Step 5: Do something with the response
        Console.WriteLine($"Response Status Code: {response.StatusCode}");
        var responseBody = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Response Body: {responseBody}");
        }
}
```

### Using middleware to transform the SAS token into a ClaimsPrincipal

The SAS token can be used as an authorization filter in an ASP.NET Core API.
This is done using middleware that checks the token in the request headers.
The middleware can be added to the ASP.NET Core pipeline during startup.


### Usage :

To use the middleware, register it in the Startup.cs file of your ASP.NET Core application. This middleware ensures 
that every request with a valid SAS token has a ClaimsPrincipal populated with relevant claims.

``` csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseMiddleware<SasTokenMiddleware>(new SasTokenValidator());
    app.UseRouting();
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}
```

## Configuration using a policy provider

You can configure the SAS policy using the `SasPolicyFromSettings` class.
This class allows you to define the policy in a configuration file (like appsettings.json)
and load it at runtime. If you want to implement a custom configuration provider,
you can create a class that implements the `ISasPolicyProvider` interface.

### Using the SasPolicyFromSettings

Add a section `SasPolicy` to the appsettings file and add the required policies. 
The policies are defined as a list of objects. You can define claims for each policy.
This is done using the `SasPolicyClaims` section. 

``` json

"SasPolicy" : [
    {
        "Skn" : "PolicyName",
        "Key" : "mySigningKey-ASecretValue",
        "UseNonce" : true,
        "HashType" : "SHA256",
        "TokenTimeOut" : 300,
        "ResourceRequest" : [ "read", "write" ]
    },
    {
        "Skn" : "SecondPolicy",
        "Key" : "mySigningKey-BSecretValue",
    }
],
"SasPolicyClaims" : [
    {
        "Skn" : "PolicyName",
        "ClaimType" : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country",
        "ClaimValue" : "nl",
    }
]

```

Reading the configuration is done while initializing the `SasPolicyFromSettings` class.

``` csharp
    public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // Add the configuration provider
        services.AddSingleton<ISasPolicyProvider, SasPolicyFromSettings>();
        
        // Add the middleware
        services.AddTransient<SasTokenMiddleware>();
        
        // Other service registrations...
    }
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseMiddleware<SasTokenMiddleware>();
        
        // Other middleware...
    }
}
```