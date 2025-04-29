using System.Collections.Generic;

namespace N2.Security.Sas
{
    public class SasPolicyOptions
    {
        public List<SASPolicy> Policies { get; set; } = [];
        public List<SASPolicyClaim> PolicyClaims { get; set; } = [];
    }
}