using System.Text.Json.Serialization;
namespace N2.Security.Sas
{
    /// <summary>  
    /// Model for SASPolicy claims  
    /// </summary>  
    public class SASPolicyClaim
    {
        public SASPolicyClaim()
        {
        }

        [JsonPropertyName("skn")]
        public string Skn { get; set; } = string.Empty;

        [JsonPropertyName("claimType")]
        public string ClaimType { get; set; } = string.Empty;

        [JsonPropertyName("claimValue")]
        public string ClaimValue { get; set; } = string.Empty;
    }
}