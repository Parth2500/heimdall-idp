namespace Heimdall.Application.Common;

/// <summary>
/// An OAuth error response (RFC 6749, section 5.2). The code is what the client sees. The detail is for the audit
/// log only and never goes into a response (D5).
/// </summary>
public sealed record OAuthError(string Code, string AuditDetail)
{
    public const string InvalidRequestCode = "invalid_request";
    public const string InvalidClientCode = "invalid_client";
    public const string InvalidGrantCode = "invalid_grant";
    public const string UnauthorizedClientCode = "unauthorized_client";
    public const string UnsupportedGrantTypeCode = "unsupported_grant_type";
    public const string InvalidScopeCode = "invalid_scope";

    /// <summary>RFC 8707: the requested resource is not valid for this client.</summary>
    public const string InvalidTargetCode = "invalid_target";

    public static OAuthError InvalidRequest(string auditDetail) => new(InvalidRequestCode, auditDetail);

    public static OAuthError InvalidClient(string auditDetail) => new(InvalidClientCode, auditDetail);

    public static OAuthError InvalidGrant(string auditDetail) => new(InvalidGrantCode, auditDetail);

    public static OAuthError UnauthorizedClient(string auditDetail) => new(UnauthorizedClientCode, auditDetail);

    public static OAuthError UnsupportedGrantType(string auditDetail) => new(UnsupportedGrantTypeCode, auditDetail);

    public static OAuthError InvalidScope(string auditDetail) => new(InvalidScopeCode, auditDetail);

    public static OAuthError InvalidTarget(string auditDetail) => new(InvalidTargetCode, auditDetail);
}
