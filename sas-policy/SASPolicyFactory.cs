using System;
using System.Text.RegularExpressions;

namespace N2.Security.Sas
{
    public static class SASPolicyFactory
    {

        public static ISasPolicy CreatePolicy(string skn, string sharedSecret, int timeoutInSeconds, HashType hashType = HashType.Sha256)
        {
            if (timeoutInSeconds < 10)
            {
                throw new ArgumentOutOfRangeException(nameof(timeoutInSeconds), "A timeout should be at least 10 s");
            }

            return new SASPolicy
            {
                Skn = skn,
                Key = sharedSecret,
                SharedResourceExpression = ".*",
                ResourceRequest = [],
                HashType = hashType,
                UseNonce = false,
                TokenTimeOut = timeoutInSeconds,
                TypeName = "SimplePolicy"
            };
        }

        public static ISasPolicy WithResource(this ISasPolicy policy, string[] resource)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }
            if (resource == null || resource.Length == 0)
            {
                return policy;
            }
            if (policy.ResourceRequest == null)
            {
                policy.ResourceRequest = resource;
            }
            else
            {
                var newResource = new string[policy.ResourceRequest.Length + resource.Length];
                Array.Copy(policy.ResourceRequest, newResource, policy.ResourceRequest.Length);
                Array.Copy(resource, 0, newResource, policy.ResourceRequest.Length, resource.Length);
                policy.ResourceRequest = newResource;
            }
            return policy;
        }

        public static ISasPolicy WithMatch(this ISasPolicy policy, string match)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }
            if (string.IsNullOrEmpty(match))
            {
                return policy;
            }
            // check if the match is a valid regex
            var regex = new Regex(match, RegexOptions.Compiled);
            policy.SharedResourceExpression = match;
            return policy;
        }

    }

}
