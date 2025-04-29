namespace N2.Security.Sas
{
    /// <summary>
    /// Model for SASPolicy claims
    /// </summary>
    public class SASPolicyClaim
    {
        public string Skn { get; set; }
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }
    }
}