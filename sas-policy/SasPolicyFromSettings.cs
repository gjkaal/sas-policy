using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.Extensions.Options;

namespace N2.Security.Sas
{
    public class SasPolicyFromSettings : ISasPolicyRepository
    {
        private readonly List<SASPolicy> policies;
        private readonly List<SASPolicyClaim> policieClaims;

        public SasPolicyFromSettings(IOptions<SasPolicyOptions> options)
        {
            policies = new List<SASPolicy>();
            policieClaims = new List<SASPolicyClaim>();

            policies.AddRange(options.Value.Policies);
            policieClaims.AddRange(options.Value.PolicyClaims);
            foreach (var policy in policies)
            {
                policy.HasClaims = policieClaims.Any(c => c.Skn == policy.Skn);
            }
        }

        public void AddOrUpdatePolicy(string keyName, ISasPolicy policy) => throw new NotSupportedException();
        public void AddPolicyClaim(string keyName, string claimType, string claimValue) => throw new NotSupportedException();

        public Task<ISasPolicy> GetPolicy(string keyName)
        {
            var policy = policies.Find(p => p.Skn == keyName);
            if (policy == null)
            {
                throw new SasPolicyNotFoundException($"Policy not found.", keyName);
            }
            return Task.FromResult<ISasPolicy>(policy);
        }

        public Task<ReadOnlyCollection<KeyValuePair<string, string>>> GetPolicyClaims(string keyName)
        {
            var result = new List<KeyValuePair<string, string>>();
            var claims = policieClaims.FindAll(c => c.Skn == keyName);
            if (claims == null)
            {
                return Task.FromResult(result.AsReadOnly());
            }
            foreach (var claim in claims)
            {
                result.Add(new KeyValuePair<string, string>(claim.ClaimType, claim.ClaimValue));
            }
            return Task.FromResult(result.AsReadOnly());
        }

        public void RemovePolicy(string keyName) => throw new NotSupportedException();
        public Task<int> SafeChangesAsync() => throw new NotSupportedException();

        public Task<bool> SigningKeyExists(string keyName)
        {
            var policy = policies.Find(p => p.Skn == keyName);
            if (policy == null)
            {
                return Task.FromResult(false);
            }
            return Task.FromResult(true);
        }
    }
}