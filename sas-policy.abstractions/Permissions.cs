namespace N2.Security.Sas
{
    /// <summary>
    ///     Enum for defining permissions
    /// </summary>
    [Flags]
    public enum Permissions
    {
        /// <summary>
        /// No permissions
        /// </summary>
        None = 0,

        /// <summary>
        /// Read permission
        /// </summary>
        Read = 1,

        /// <summary>
        /// Write permission
        /// </summary>
        Write = 2,

        /// <summary>
        /// Manage permission
        /// </summary>
        Manage = 4,

        /// <summary>
        /// Delete permission
        /// </summary>
        Detele = 8,
    }
}