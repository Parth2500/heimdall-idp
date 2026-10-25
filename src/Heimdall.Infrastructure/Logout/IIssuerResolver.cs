namespace Heimdall.Infrastructure.Logout;

/// <summary>
/// The issuer URL of a tenant, for work outside a request. The Api layer builds it from configuration (D19, D21), the
/// same way it builds the issuer of a request.
/// </summary>
public interface IIssuerResolver
{
    string IssuerFor(string tenantHost);
}
