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

## Javascript Client

The client can be used in a JavaScript application to generate a SAS token and use it in an HTTP request.
Save the following code in a file named `sasTokenUtils.js`. These methods are adapted to use 
JavaScript's built-in crypto module for hashing.

``` javascript
const crypto = require('crypto');

/**
 * Calculates the hash of a string using the specified hash type and shared secret.
 * @param {string} sharedSecret - The shared secret used for hashing.
 * @param {string} hashType - The hash type (e.g., 'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512').
 * @param {string} stringToSign - The string to be hashed.
 * @returns {string} - The calculated hash.
 */
function calculateHash(sharedSecret, hashType, stringToSign) {
    let hmac;
    switch (hashType.toUpperCase()) {
        case 'MD5':
            const md5 = crypto.createHash('md5');
            md5.update(stringToSign + '\n' + sharedSecret, 'utf8');
            return md5.digest('hex').toLowerCase();
        case 'SHA1':
            hmac = crypto.createHmac('sha1', sharedSecret);
            break;
        case 'SHA256':
            hmac = crypto.createHmac('sha256', sharedSecret);
            break;
        case 'SHA384':
            hmac = crypto.createHmac('sha384', sharedSecret);
            break;
        case 'SHA512':
            hmac = crypto.createHmac('sha512', sharedSecret);
            break;
        default:
            throw new Error(`Hashing using ${hashType} is not supported`);
    }

    hmac.update(stringToSign, 'utf8');
    return hmac.digest('base64');
}

/**
 * Calculates the signature of a SAS token.
 * @param {Object} token - The SAS token parameters.
 * @param {string} sharedSecret - The shared secret used for hashing.
 * @param {boolean} useNonce - Whether to include the nonce in the signature.
 * @param {string} hashType - The hash type (e.g., 'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512').
 * @param {Array<string>} [additionalKeys] - Additional keys to include in the signature.
 * @returns {string} - The calculated signature.
 */
function calcSignature(token, sharedSecret, useNonce, hashType, additionalKeys = []) {
    if (sharedSecret.length < 20) {
        throw new Error('Invalid signing key: The shared secret must be at least 20 characters long.');
    }

    let stringToSign = encodeURIComponent(token.SharedResource.join(',')) + '\n';

    if (additionalKeys) {
        for (const key of additionalKeys) {
            if (!token.AdditionalValues || !token.AdditionalValues[key]) {
                throw new Error(`Value is missing from additional values: ${key}`);
            }
            stringToSign += `${key}=${encodeURIComponent(token.AdditionalValues[key])}\n`;
        }
    }

    if (useNonce) {
        if (!token.Nonce) {
            throw new Error('Nonce is required.');
        }
        stringToSign += `${encodeURIComponent(token.Nonce)}\n`;
    }

    stringToSign += token.Expiry;
    return calculateHash(sharedSecret, hashType, stringToSign);
}

module.exports = { calculateHash, calcSignature };
```

Example usage of the client to generate a SAS token and use it in an HTTP request, in a real world scenario,

``` javascript
const axios = require('axios');
const { calcSignature } = require('./sasTokenUtils'); // Import the calcSignature function

// Example token parameters
const token = {
    SharedResource: ['https://filestorage.example.com/files/myfile.txt'], // The resource to access
    AdditionalValues: { permission: 'read' }, // Additional parameters (e.g., permissions)
    Nonce: 'uniqueNonce123', // Unique identifier to prevent replay attacks
    Expiry: Math.floor(Date.now() / 1000) + 600, // Token valid for 10 minutes
};

// Shared secret and hash type
const sharedSecret = 'superSecretKey1234567890';
const hashType = 'SHA256';
const useNonce = true;
const additionalKeys = ['permission'];

async function accessFile() {
    try {
        // Step 1: Calculate the signature
        const signature = calcSignature(token, sharedSecret, useNonce, hashType, additionalKeys);

        // Step 2: Construct the Base64-encoded token
        const tokenString = `skn=${encodeURIComponent('fileAccessKey')}`
            + `&sr=${encodeURIComponent(token.SharedResource.join(','))}`
            + `&se=${token.Expiry}`
            + `&sig=${encodeURIComponent(signature)}`
            + `&nonce=${encodeURIComponent(token.Nonce)}`;
        const base64EncodedToken = Buffer.from(tokenString).toString('base64');

        // Step 3: Make the HTTP request to access the file
        const response = await axios.get(token.SharedResource[0], {
            headers: {
                Authorization: `Bearer ${base64EncodedToken}`, // Include the token in the Authorization header
            },
        });

        // Step 4: Handle the response
        console.log('File Content:', response.data);
    } catch (error) {
        console.error('Error accessing file:', error.message);
    }
}

// Execute the function
accessFile();


```
\
