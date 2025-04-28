using Microsoft.VisualStudio.TestTools.UnitTesting;

using N2.Security.Sas;

namespace SasPolicy.Tests
{
    [TestClass]
    public class SasPolicyfactoryShould
    {
        [TestMethod]
        public void CreateValidPolicies()
        {
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            Assert.IsNotNull(policy);
        }
    }
}