namespace N2.Security.Sas
{
    /// <summary>
    ///     Interface ISASPolicy
    /// </summary>
    /// <remarks>no comments</remarks>
    public interface ISasPolicy
    {
        /// <summary>
        ///     Gets or sets the signing key name
        /// </summary>
        /// <value>The SKN.</value>
        /// <remarks>no comments</remarks>
        string Skn { get; set; }

        /// <summary>
        /// Gets or sets the signing key.
        /// </summary>
        /// <value>The key.</value>
        /// <remarks>no comments</remarks>
        string Key { get; set; }

        /// <summary>
        /// Gets or sets the name of the type.
        /// </summary>
        /// <value>The name of the type.</value>
        /// <remarks>no comments</remarks>
        string TypeName { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether use a nonce in the signature.
        /// </summary>
        /// <value><c>true</c> if [use nonce]; otherwise, <c>false</c>.</value>
        bool UseNonce { get; set; }

        /// <summary>
        ///     Gets or sets the type of the hash.
        /// </summary>
        /// <value>The type of the hash.</value>
        HashType HashType { get; set; }

        /// <summary>
        ///     Gets or sets the token time out.
        /// </summary>
        /// <value>The token time out.</value>
        int TokenTimeOut { get; set; }

        /// <summary>
        /// The permissions requested with this token
        /// </summary>
        string[] ResourceRequest { get; set; }

        /// <summary>
        /// Regular expression that is used to match with the resource name.
        /// A default value is ".*" which means all resources are allowed.
        /// </summary>
        string SharedResourceExpression { get; set; }

        /// If any additional keys are required, add them to this list
        ICollection<string> AdditionalKeys { get; set; }
    }
}