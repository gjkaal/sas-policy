using System.Collections.ObjectModel;

namespace N2.Security.Sas
{
    public interface ISasPolicyRepository
    {
        Task<bool> SigningKeyExists(string keyName);
        Task<ISasPolicy> GetPolicy(string keyName);
        void AddOrUpdatePolicy(string keyName, ISasPolicy policy);
        void RemovePolicy(string keyName);
        void AddPolicyClaim(string keyName, string claimType, string claimValue);
        Task<ReadOnlyCollection<KeyValuePair<string, string>>> GetPolicyClaims(string keyName);
        Task<int> SafeChangesAsync();
    }
}