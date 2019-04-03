namespace Nice2Experience.Security.Sas
{
    public interface ISasTokenValidationResult
    {
        bool Success { get; }
        TokenResponseCode TokenResponseCode { get; }
        string Resource { get; }

    }

}