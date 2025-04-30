using System;
using System.Text;

using Microsoft.Extensions.Primitives;
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
            var uri = new Uri("http://localhost");
            var policy = SASPolicyFactory.CreatePolicy("a", "This is a valid secret", 60);
            var token = SasTokenFactory.Create(uri, policy);
            Assert.IsNotNull(token);
            var queryString = token.ToQueryString();
            Console.WriteLine(queryString);
        }

        [DataTestMethod]
        [DataRow("skn=a&sr=b&se=c&sig=e&nonce=10", "a", "b")]
        [DataRow("skn=a&sr=c,d&sig=e&nonce=10", "a", "c,d")]
        [DataRow("skn=a&sig=e&nonce=10", "a", null)]
        public void ParseTokenParametersFromQueryString(string queryString, string expected, string? resource)
        {
            var token = SasTokenFactory.Parse(queryString);
            Assert.IsNotNull(token);
            Assert.AreEqual(expected, token.SigningKeyName);
            Assert.AreEqual(resource, token.SharedResource);
        }

        [DataTestMethod]
        [DataRow("skn=a&sr=b&se=c&sig=e&nonce=10", "a")]
        public void ParseTokenParametersFromBase64(string queryString, string expected)
        {
            var data = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(queryString));
            var headerData = new StringValues(["bearer", data]);

            // Any indicator is allowed
            var token = SasTokenFactory.Parse(headerData);
            Assert.IsNotNull(token);
            Assert.AreEqual(expected, token.SigningKeyName);

            // Without type is allowed
            headerData = new StringValues([data]);
            token = SasTokenFactory.Parse(headerData);
            Assert.IsNotNull(token);
            Assert.AreEqual(expected, token.SigningKeyName);
        }
    }
}