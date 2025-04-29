using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using N2.Security.Sas;

[TestClass]
public class WithPolicyRepositoryFromSettings
{
    private readonly IConfiguration configuration;
    private readonly IOptions<SasPolicyOptions> policyOptions;

    public WithPolicyRepositoryFromSettings()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>()
            {
                ["SasPolicy:Policies:0:Skn"] = "SomeKey",
                ["SasPolicy:Policies:0:Key"] = "signingKey",
                ["SasPolicy:Policies:0:ResourceRequest:0"] = "read",
                ["SasPolicy:Policies:0:ResourceRequest:1"] = "write",
                ["SasPolicy:Policies:0:TypeName"] = "MyPolicy",
                ["SasPolicy:Policies:0:UseNonce"] = "true",
                ["SasPolicy:Policies:0:HashType"] = "Sha512",
                ["SasPolicy:Policies:0:TokenTimeOut"] = "14400",
                ["SasPolicy:Policies:0:AdditionalKeys:0"] = "ExtraKey",
                ["SasPolicy:Policies:1:Skn"] = "Minimal",
                ["SasPolicy:Policies:1:Key"] = "signingKey",
                ["SasPolicy:PolicyClaims:0:Skn"] = "SomeKey",
                ["SasPolicy:PolicyClaims:0:ClaimType"] = ClaimTypes.Spn,
                ["SasPolicy:PolicyClaims:0:ClaimValue"] = "ClaimValue",
                ["SasPolicy:PolicyClaims:1:Skn"] = "SomeKey",
                ["SasPolicy:PolicyClaims:1:ClaimType"] = ClaimTypes.Name,
                ["SasPolicy:PolicyClaims:1:ClaimValue"] = "NameValue",
            });

        // Build the configuration
        configuration = builder.Build();
        var options = new SasPolicyOptions();
        configuration.Bind("SasPolicy", options);
        policyOptions = Options.Create(options);
    }

    [TestMethod]
    public void OptionsCanBeReadFromConfiguration()
    {
        var options = new SasPolicyOptions();
        configuration.Bind("SasPolicy", options);
        Assert.IsNotNull(options);
        Assert.IsNotNull(options.Policies);
        Assert.IsNotNull(options.PolicyClaims);
        Assert.IsTrue(options.Policies.Count > 0);
        Assert.IsTrue(options.PolicyClaims.Count > 0);
    }

    [TestMethod]
    public void ItInitializesFromConfiguration()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);
        Assert.IsNotNull(policyRepository);
        Assert.IsInstanceOfType<ISasPolicyRepository>(policyRepository);
    }

    [TestMethod]
    public async Task ItCanLocatePolicies()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);
        var existingKey = await policyRepository.SigningKeyExists("SomeKey");
        var notExistingKey = await policyRepository.SigningKeyExists("NoValidKey");
        Assert.IsTrue(existingKey);
        Assert.IsFalse(notExistingKey);
    }

    [TestMethod]
    public async Task ItCanGetPolicy()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);
        var policy = await policyRepository.GetPolicy("SomeKey");
        Assert.IsNotNull(policy);
        Assert.IsInstanceOfType<ISasPolicy>(policy);
        Assert.AreEqual("SomeKey", policy.Skn);
        Assert.AreEqual("signingKey", policy.Key);
        Assert.AreEqual("MyPolicy", policy.TypeName);
        Assert.AreEqual(HashType.Sha512, policy.HashType);
        Assert.AreEqual(14400, policy.TokenTimeOut);
    }

    [TestMethod]
    public async Task ItCanGetMinimalKeyPolicy()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);
        var policy = await policyRepository.GetPolicy("Minimal");
        Assert.IsNotNull(policy);
        Assert.IsInstanceOfType<ISasPolicy>(policy);
        Assert.AreEqual("Minimal", policy.Skn);
        Assert.AreEqual("signingKey", policy.Key);
        Assert.AreEqual("SASPolicy", policy.TypeName);
        Assert.AreEqual(HashType.None, policy.HashType);
        Assert.AreEqual(300, policy.TokenTimeOut);

    }

    [TestMethod]
    public async Task ItThrowsNotFoundForNonExistingKey()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);
        await Assert.ThrowsAsync<SasPolicyNotFoundException>(() => policyRepository.GetPolicy("NoValidKey"));
    }

    [TestMethod]
    public async Task ItCanGetPolicyClaims()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);
        var claims = await policyRepository.GetPolicyClaims("SomeKey");
        Assert.IsNotNull(claims);
        Assert.IsInstanceOfType<ICollection<KeyValuePair<string, string>>>(claims);
        Assert.AreEqual(2, claims.Count);
        Assert.IsTrue(claims.Contains(new KeyValuePair<string, string>(ClaimTypes.Spn, "ClaimValue")));
        Assert.IsTrue(claims.Contains(new KeyValuePair<string, string>(ClaimTypes.Name, "NameValue")));
    }

    [TestMethod]
    public async Task ItCannotUpdatePolicy()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);
        var policy = await policyRepository.GetPolicy("SomeKey");

        Assert.Throws<NotSupportedException>(() => policyRepository.AddOrUpdatePolicy("SomeKey", policy));
    }

    [TestMethod]
    public void ItCannotAddPolicy()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);

        var newPolicy = SASPolicyFactory.CreatePolicy("NewKey", "NewSecret", 60);
        Assert.Throws<NotSupportedException>(() => policyRepository.AddOrUpdatePolicy("NewKey", newPolicy));
    }

    [TestMethod]
    public void ItCannotAddPolicyClaim()
    {
        var policyRepository = new SasPolicyFromSettings(policyOptions);

        Assert.Throws<NotSupportedException>(() => policyRepository.AddPolicyClaim("SomeKey", ClaimTypes.Spn, "ClaimValue"));
    }
}