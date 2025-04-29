namespace N2.Security.Sas
{
    /// <summary>
    ///     Enum HashType
    /// </summary>
    public enum HashType
    {
        /// <summary>
        ///     The none
        /// </summary>
        None = 0,

        /// <summary>
        ///     The default MD5 algorithm
        /// </summary>
        MD5 = 1,

        /// <summary>
        ///     The sha1
        /// </summary>
        Sha1 = 32772,

        /// <summary>
        /// The sha-2 hashes
        /// </summary>
        Sha256 = 32780,
        Sha384 = 32781,
        Sha512 = 32782,

        /// <summary>
        /// The sha-3 hashes
        /// </summary>
        SHA3_256 = 32783,
        SHA3_384 = 32785,
        SHA3_512 = 32786,
    }
}