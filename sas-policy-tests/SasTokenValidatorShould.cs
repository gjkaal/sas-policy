using System;
using System.Threading.Tasks;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using Moq;

using N2.Security.Sas;

namespace SasPolicy.Tests
{
    [TestClass]
    public class SasTokenValidatorShould
    {
        [TestMethod]
        public async Task AcceptPolicyToValidateQuerystring()
        {
            var resourceRequest = new Uri("http://localhost");
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            var token = SasTokenFactory.Create(resourceRequest, policy)
                .WithValue("Permissions", ["read", "write"]);
            var signature = token.ToQueryString();
            var policyRepository = new Mock<ISasPolicyRepository>();

            policyRepository.Setup(x => x.GetPolicy(It.IsAny<string>()))
                .ReturnsAsync(policy);

            var validator = new SasTokenValidator(policyRepository.Object);
            var validationResult = await validator.Validate(new Uri("http://localhost"), signature);
            Assert.IsTrue(validationResult.Success);
            Assert.AreEqual("http://localhost/", validationResult.Resource);

            Assert.AreEqual(TokenResponseCode.TokenAccepted, validationResult.TokenResponseCode);
            Assert.Contains("read", validationResult.Permissions);
            Assert.Contains("write", validationResult.Permissions);
        }

        [TestMethod]
        public async Task FailWhenResourceNotAllowed()
        {
            var resourceRequest = new Uri("http://localhost");

            // only allow read permissions
            var policy = SASPolicyFactory
                .CreatePolicy("a", "This is a valid secret", 60)
                .WithPermissions(["read"]);

            // Token request with read and write permissions
            var token = SasTokenFactory.Create(resourceRequest, policy)
                .WithValue("Permissions", ["read", "write"]);

            var signature = token.ToQueryString();
            var policyRepository = new Mock<ISasPolicyRepository>();

            policyRepository.Setup(x => x.GetPolicy(It.IsAny<string>()))
                .ReturnsAsync(policy);

            var validator = new SasTokenValidator(policyRepository.Object);
            var validationResult = await validator.Validate(new Uri("http://localhost"), signature);
            Assert.IsFalse(validationResult.Success);
            Assert.AreEqual(TokenResponseCode.PolicyFailed, validationResult.TokenResponseCode);
            Assert.AreEqual("http://localhost/", validationResult.Resource);
        }

        [TestMethod]
        public async Task SuccessWhenPathAllowed()
        {
            var resourceRequest = new Uri("http://localhost/path");
            var policy = SASPolicyFactory
                .CreatePolicy("a", "This is a valid secret", 60)
                .WithMatch("http://localhost");
            var token = SasTokenFactory.Create(resourceRequest, policy);
            var signature = token.ToQueryString();
            var policyRepository = new Mock<ISasPolicyRepository>();

            policyRepository.Setup(x => x.GetPolicy(It.IsAny<string>()))
                .ReturnsAsync(policy);

            var validator = new SasTokenValidator(policyRepository.Object);
            var validationResult = await validator.Validate(resourceRequest, signature);
            Assert.IsTrue(validationResult.Success);
            Assert.AreEqual(TokenResponseCode.TokenAccepted, validationResult.TokenResponseCode);
            Assert.AreEqual("http://localhost/path", validationResult.Resource);
        }

        [TestMethod]
        public async Task FailWhenPathNotAllowed()
        {
            var resourceRequest = new Uri("http://localhost/path");
            var policy = SASPolicyFactory
                .CreatePolicy("a", "This is a valid secret", 60)
                .WithMatch("https://localhost");
            var token = SasTokenFactory.Create(resourceRequest, policy);
            var signature = token.ToQueryString();
            var policyRepository = new Mock<ISasPolicyRepository>();

            policyRepository.Setup(x => x.GetPolicy(It.IsAny<string>()))
                .ReturnsAsync(policy);

            var validator = new SasTokenValidator(policyRepository.Object);
            var validationResult = await validator.Validate(resourceRequest, signature);
            Assert.IsFalse(validationResult.Success);
            Assert.AreEqual(TokenResponseCode.SharedResourceExpressionFailed, validationResult.TokenResponseCode);
            Assert.AreEqual("http://localhost/path", validationResult.Resource);
        }
    }
}
