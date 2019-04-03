namespace Nice2Experience.SasPolicy
{
    /// <summary>
    ///     Interface for managing sas policies
    /// </summary>
    public interface ISasPolicyManager
    {
        /// <summary>
        ///     Get the policy key of the specified keyName
        /// </summary>
        /// <param name="keyName">Name of the Key</param>
        /// <returns>The sas policy key</returns>
        string GetKey(string keyName);


        /// <summary>
        ///     Gets the policy using the keyname as the identifier.
        /// </summary>
        /// <param name="keyName">Name of the key.</param>
        /// <returns>SASPolicy.</returns>
        ISasPolicy GetPolicy(string keyName);
    }
}