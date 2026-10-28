using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Tokens;

/// <param name="ClientId">From the Basic header (confidential client) or the body (public client).</param>
/// <param name="ClientSecret">From the Basic header, or null for a public client.</param>
/// <param name="Token">The <c>token</c> parameter.</param>
public sealed record RevocationRequest(string? ClientId, string? ClientSecret, string? Token, string? ClientAssertion = null);

/// <summary>What a revocation did. The endpoint returns 200 for each value (RFC 7009, section 2.2).</summary>
public enum RevocationOutcome
{
    /// <summary>The token was a refresh token of the caller. Its family is now revoked.</summary>
    FamilyRevoked,

    /// <summary>The family of the caller's refresh token was revoked before.</summary>
    AlreadyRevoked,

    /// <summary>The refresh token belongs to another client. Nothing changed.</summary>
    ForeignToken,

    /// <summary>No refresh token has this value. It can be an access token, which Heimdall cannot revoke (D8).</summary>
    NotFound,
}

/// <summary>
/// <c>POST /oauth/v1/revoke</c> (RFC 7009). A refresh token revokes its whole family, including the newest token. An
/// access token is a stateless JWT that lives 5 minutes (D8): Heimdall cannot revoke it and returns 200.
/// </summary>
/// <remarks>
/// The caller gets 200 for an unknown, expired, revoked, or foreign token, so the response does not show whether a
/// token existed (threat model, /revoke, Information disclosure). Only a malformed request or a failed client
/// authentication gets an error. The token hint (<c>token_type_hint</c>) is not used: one indexed read finds a refresh
/// token, and a miss means "not a refresh token" for any hint.
/// </remarks>
public sealed class TokenRevocation
{
    private readonly ClientAuthenticator _authenticator;
    private readonly ITokenStore _tokens;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public TokenRevocation(ClientAuthenticator authenticator, ITokenStore tokens, IAuditLog audit, TimeProvider time)
    {
        _authenticator = authenticator;
        _tokens = tokens;
        _audit = audit;
        _time = time;
    }

    public async Task<Result<RevocationOutcome>> RevokeAsync(
        RequestContext context,
        RevocationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        // A suspended tenant can still revoke. Revocation only removes access, so refusing it would help no one.
        var authentication = await _authenticator
            .AuthenticateAsync(context.Tenant.Id, context.Issuer, request.ClientId, request.ClientSecret, request.ClientAssertion, cancellationToken)
            .ConfigureAwait(false);
        if (!authentication.IsSuccess)
        {
            // Audited like a failed authentication at /token. Otherwise /revoke would be a secret-guessing oracle
            // with no audit trail.
            await WriteAuditAsync(
                context,
                AuditEventTypes.RevocationRefused,
                null,
                new Dictionary<string, string>
                {
                    ["client_id"] = request.ClientId is { Length: > 128 } id ? id[..128] : request.ClientId ?? string.Empty,
                    ["error"] = authentication.Error.Code,
                    ["reason"] = authentication.Error.AuditDetail,
                },
                cancellationToken).ConfigureAwait(false);
            return Result.Failure<RevocationOutcome>(authentication.Error);
        }

        if (string.IsNullOrEmpty(request.Token))
        {
            return Result.Failure<RevocationOutcome>(OAuthError.InvalidRequest("token missing"));
        }

        var client = authentication.Value;
        var token = await _tokens.FindRefreshTokenAsync(context.Tenant.Id, TokenHash.Compute(request.Token), cancellationToken)
            .ConfigureAwait(false);
        if (token is null)
        {
            return Result.Success(RevocationOutcome.NotFound);
        }

        var family = await _tokens.FindFamilyAsync(context.Tenant.Id, token.FamilyId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("A refresh token without its family.");

        if (family.ClientPk != client.Id)
        {
            // Threat model, /revoke, Spoofing: a client cannot revoke the tokens of another client.
            await WriteAuditAsync(
                context,
                AuditEventTypes.RevocationRefused,
                family,
                new Dictionary<string, string> { ["client_id"] = client.ClientId, ["reason"] = "refresh token of another client" },
                cancellationToken).ConfigureAwait(false);
            return Result.Success(RevocationOutcome.ForeignToken);
        }

        // Any token of the family revokes it, even a used one. Revocation only removes access, so it is not reuse.
        var now = _time.GetUtcNow();
        var revoked = await _tokens.RevokeFamilyAsync(context.Tenant.Id, family.Id, FamilyRevocationReason.UserLogout, now, cancellationToken)
            .ConfigureAwait(false);
        if (!revoked)
        {
            return Result.Success(RevocationOutcome.AlreadyRevoked);
        }

        await WriteAuditAsync(
            context,
            AuditEventTypes.FamilyRevoked,
            family,
            new Dictionary<string, string> { ["reason"] = "user_logout", ["source"] = "revocation_endpoint", ["client_id"] = client.ClientId },
            cancellationToken).ConfigureAwait(false);
        return Result.Success(RevocationOutcome.FamilyRevoked);
    }

    private Task WriteAuditAsync(
        RequestContext context,
        string type,
        TokenFamily? family,
        Dictionary<string, string> data,
        CancellationToken cancellationToken) =>
        _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                type,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                subjectUserId: family?.UserId,
                clientPk: family?.ClientPk,
                familyId: family?.Id,
                data: data),
            cancellationToken);
}
