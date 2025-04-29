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
            string[] resourceRequest = ["read", "write"];
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            var token = SasTokenFactory.Create(resourceRequest, policy);
            var signature = token.ToQueryString();
            var policyRepository = new Mock<ISasPolicyRepository>();

            policyRepository.Setup(x => x.GetPolicy(It.IsAny<string>()))
                .ReturnsAsync(policy);

            var validator = new SasTokenValidator(policyRepository.Object);
            var validationResult = await validator.Validate(new Uri("http://localhost"), signature);
            Assert.IsTrue(validationResult.Success);
            Assert.AreEqual("read,write", validationResult.Resource);
        }

        [TestMethod]
        public async Task FailWhenResourceNotAllowed()
        {
            string[] resourceRequest = ["read", "write"];
            var policy = SASPolicyFactory
                .CreatePolicy("a", "This is a valid secret", 60)
                .WithResource(["read"]);
            var token = SasTokenFactory.Create(resourceRequest, policy);
            var signature = token.ToQueryString();
            var policyRepository = new Mock<ISasPolicyRepository>();

            policyRepository.Setup(x => x.GetPolicy(It.IsAny<string>()))
                .ReturnsAsync(policy);

            var validator = new SasTokenValidator(policyRepository.Object);
            var validationResult = await validator.Validate(new Uri("http://localhost"), signature);
            Assert.IsFalse(validationResult.Success);
            Assert.AreEqual(TokenResponseCode.PolicyFailed, validationResult.TokenResponseCode);
            Assert.AreEqual("read,write", validationResult.Resource);
        }

        [TestMethod]
        public async Task FailWhenPathNotAllowed()
        {
            string[] resourceRequest = ["read", "write"];
            var policy = SASPolicyFactory
                .CreatePolicy("a", "This is a valid secret", 60)
                .WithMatch("https://localhost");
            var token = SasTokenFactory.Create(resourceRequest, policy);
            var signature = token.ToQueryString();
            var policyRepository = new Mock<ISasPolicyRepository>();

            policyRepository.Setup(x => x.GetPolicy(It.IsAny<string>()))
                .ReturnsAsync(policy);

            var validator = new SasTokenValidator(policyRepository.Object);
            var validationResult = await validator.Validate(new Uri("http://localhost"), signature);
            Assert.IsFalse(validationResult.Success);
            Assert.AreEqual(TokenResponseCode.SharedResourceExpressionFailed, validationResult.TokenResponseCode);
            Assert.AreEqual("read,write", validationResult.Resource);
        }
    }
}
