using System;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using N2.Security.Sas;

namespace SasPolicy.Tests
{
    [TestClass]
    public class SasTokenFactoryShould
    {
        [TestMethod]
        public void UsePoliciesToCreateSasTokens()
        {
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            var token = SasTokenFactory.Create(["CalculateThis"], policy);
            Assert.IsNotNull(token);
            var queryString = token.ToQueryString();
            Console.WriteLine(queryString);
        }
    }
}