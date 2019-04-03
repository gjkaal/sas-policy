namespace Nice2Experience.SasPolicy
{
    public interface ISasTokenValidationResult
    {
        bool Success { get; }
        TokenResponseCode TokenResponseCode { get; }
        string Resource { get; }

    }

}