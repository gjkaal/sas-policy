using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace N2.Security.Sas
{
    public static class SasTokenParametersExtensions
    {
        public static ISasTokenParameters WithValue(this ISasTokenParameters token, string key, string[]? values)
        {
            if (values is null || values.Length == 0)
            {
                return token;
            }
            if (token.AdditionalValues == null)
            {
                token.AdditionalValues = new Dictionary<string, string>();
            }
            if (token.AdditionalValues.ContainsKey(key))
            {
                token.AdditionalValues[key] = string.Join(",", values);
            }
            else
            {
                token.AdditionalValues.Add(key, string.Join(",", values));
            }
            return token;
        }
    }


    /// <summary>
    ///     represents a SAS-token. (Shared Access Signature)
    /// </summary>
    public class SasTokenParameters : ISasTokenParameters
    {
        /// <summary>
        ///     skn
        /// </summary>
        [JsonPropertyName("skn")]
        [JsonRequired]
        public string? SigningKeyName { get; set; } = string.Empty;

        /// <summary>
        ///     sr
        /// </summary>
        [JsonPropertyName("sr")]
        [JsonRequired]
        public string? SharedResource { get; set; } = string.Empty;

        /// <summary>
        ///     sig
        /// </summary>
        [JsonPropertyName("sig")]
        [JsonRequired]
        public string? Signature { get; set; }

        /// <summary>
        ///     se
        /// </summary>
        [JsonPropertyName("se")]
        [JsonRequired]
        public int Expiry { get; set; } = 300;

        /// <summary>
        ///    nonce
        /// </summary>
        [JsonPropertyName("nonce")]
        public string? Nonce { get; set; }

        /// <summary>
        ///     Other values in request, used for signature
        /// </summary>
        [JsonPropertyName("xval")]
        public IDictionary<string, string>? AdditionalValues { get; set; }

        /// <summary>
        /// If parsed from a query string, this value is set is key elements are missing
        /// </summary>
        [JsonIgnore]
        public bool Invalid { get; set; }
    }
}