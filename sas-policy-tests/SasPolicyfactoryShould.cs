using Xunit;
using Xunit.Abstractions;

using Nice2Experience.Security.Sas;

namespace SasPolicy.Tests
{

    public class SasPolicyfactoryShould
    {
        [Fact]
        public void CreateValidPolicies()
        {
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            Assert.NotNull(policy);
        }
    }

    public class SasTokenFactoryShould
    {
        internal readonly ITestOutputHelper _outputHelper;
        public SasTokenFactoryShould(ITestOutputHelper outputHelper)
        {
            _outputHelper = outputHelper;
        }

        [Fact]
        public void UsePoliciesToCreateSasTokens()
        {
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            var token = SasTokenFactory.Create("CalculateThis", policy);
            Assert.NotNull(token);
            var queryString = token.ToQueryString();
            _outputHelper.WriteLine(queryString);
        }
    }

    public class SasTokenValidatorShould
    {
        internal readonly ITestOutputHelper _outputHelper;
        public SasTokenValidatorShould(ITestOutputHelper outputHelper)
        {
            _outputHelper = outputHelper;
        }

        [Fact]
        public void AcceptPolicyToValidateQuerystring()
        {
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            var token = SasTokenFactory.Create("CalculateThis", policy);
            var queryString = token.ToQueryString();

            var validator = new SasTokenValidator(policy);
            var validationResult = validator.Validate(queryString);
            Assert.True(validationResult.Success);
        }
    }

}