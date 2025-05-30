namespace N2.Security.Sas
{
    /// <summary>
    /// Interface for SAS token parameters
    /// </summary>
    public interface ISasTokenParameters
    {
        /// <summary>
        /// The expired time of the token in seconds since epoch (Unix time).
        /// </summary>
        int Expiry { get; set; }

        /// <summary>
        /// A unique identifier for the token, used to prevent replay attacks.
        /// </summary>
        string? Nonce { get; set; }

        /// <summary>
        /// The shared resource that the token grants access to, e.g. a URL or file path.
        /// </summary>
        string? SharedResource { get; set; }

        /// <summary>
        /// The signature of the token, used to verify its authenticity.
        /// </summary>
        string? Signature { get; set; }

        /// <summary>
        /// The name of the signing key used to create the token's signature.
        /// </summary>
        string? SigningKeyName { get; set; }

        /// <summary>
        /// Additional values that should be included in the token, e.g. query parameters
        /// or permissions requested for the resource.
        /// </summary>
        IDictionary<string, string>? AdditionalValues { get; set; }
    }
}
