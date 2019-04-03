namespace Nice2Experience.SasPolicy
{
    /// <summary>
    ///     Interface ISASPolicy
    /// </summary>
    /// <remarks>no comments</remarks>
    public interface ISasPolicy
    {
        /// <summary>
        ///     Gets or sets the resource identifier.
        /// </summary>
        /// <value>The resource identifier.</value>
        /// <remarks>no comments</remarks>
        string SharedResourceExpression { get; set; }

        /// <summary>
        ///     Gets or sets the signing key name
        /// </summary>
        /// <value>The SKN.</value>
        /// <remarks>no comments</remarks>
        string Skn { get; set; }

        /// <summary>
        ///     Gets or sets the signing key.
        /// </summary>
        /// <value>The key.</value>
        /// <remarks>no comments</remarks>
        string Key { get; set; }

        /// <summary>
        ///     Gets or sets the name of the type.
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
        /// Gets or sets the sharding key.
        /// </summary>
        /// <value>The tenant.</value>
        int ShardingKey { get; set; }

        /// <summary>
        /// The permissions requested with this token
        /// </summary>
        Permissions Permissions { get; set; }


    }
}