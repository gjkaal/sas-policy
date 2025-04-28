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

        // Send the request
        var response = await httpClient.SendAsync(request);

        // Step 4: Do something with the response
        Console.WriteLine($"Response Status Code: {response.StatusCode}");
        var responseBody = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Response Body: {responseBody}");
        }
}
```

### Example authorization filter for an ASP.NET Core API

The SAS token can be used as an authorization filter in an ASP.NET Core API.
This is done using middleware that checks the token in the request headers.
The middleware can be added to the ASP.NET Core pipeline during startup.

This example demonstrates how to create a custom authorization filter 
that checks for a valid SAS token in the request headers.

``` csharp
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using N2.Security.Sas;

public class SasTokenMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ISasTokenValidator _sasTokenValidator;
    private readonly IClaimsRepository _claimsRepository;

    public SasTokenMiddleware(
        RequestDelegate next, 
        ISasTokenValidator sasTokenValidator,
        IClaimsRepository claimsRepository)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _sasTokenValidator = sasTokenValidator ?? throw new ArgumentNullException(nameof(sasTokenValidator));
        _keyRepository = _keyRepository ?? throw new ArgumentNullException(nameof(keyRepository));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Extract the token from the Authorization header
        var authorizationHeader = context.Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Authorization header missing or invalid.");
            return;
        }

        var tokenString = authorizationHeader.Substring("Bearer ".Length).Trim();

        // Validate the token
        var token = SasTokenFactory.Parse(tokenString);
        var validationResult = _sasTokenValidator.Validate(token);

        if (!validationResult.Success)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            // TODO: Log the validation error
            // TODO: You should not disclose the reason for failure in production
            await context.Response.WriteAsync($"Token validation failed: {validationResult.TokenResponseCode}");
            return;
        }

        // Check if the signing key is valid, returns null if not found
        var signingKeyClaims = _claimsRepository.GetClaimsByName(token.SigningKeyName);
        if (signingKeyClaims == null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            // TODO: Log the validation error
            // TODO: You should not disclose the reason for failure in production
            await context.Response.WriteAsync("Invalid signing key.");
            return;
        }

        // Create claims based on the token
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, token.SigningKeyName),
            new Claim("SharedResource", token.SharedResource),
            new Claim("Expiry", token.Expiry.ToString())
        };

        // Add additional claims based on the `skn` parameter
        if (signingKeyClaims.Any)
        {
            foreach (var claim in signingKeyClaims)
            {
                claims.Add(new Claim(claim.Type, claim.Value));
            }
        }

        // Create a ClaimsIdentity and set it on the HttpContext
        var identity = new ClaimsIdentity(claims, "SasToken");
        context.User = new ClaimsPrincipal(identity);

        // Call the next middleware in the pipeline
        await _next(context);
    }
}
```

### Explanation:

1.	__Extract Token:__ The middleware extracts the token from the Authorization header.
2.	__Validate Token:__ The SasTokenValidator is used to validate the token.
3.  __Get Signing Key Claims:__ Signing key claims are retrieved based on the token's SigningKeyName.
3.	__Create Claims:__ Claims are created based on the token's properties, such as SigningKeyName, SharedResource, and Expiry.
4.	__Set ClaimsPrincipal:__ A ClaimsPrincipal is created and assigned to HttpContext.User.
5.	__Pass to Next Middleware:__ If validation succeeds, the request is passed to the next middleware in the pipeline.

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