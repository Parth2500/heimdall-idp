using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Domain.Audit;

namespace Heimdall.Application.Authorization;

/// <param name="ClientId">From the Basic header (confidential client) or the body (public client).</param>
/// <param name="ClientSecret">From the Basic header, or null for a public client.</param>
/// <param name="Parameters">The form parameters: every authorization parameter of the request.</param>
/// <param name="DpopProof">The DPoP header, or null.</param>
public sealed record PushRequest(
    string? ClientId, string? ClientSecret, IReadOnlyDictionary<string, string> Parameters, string? DpopProof, string? ClientAssertion = null);

/// <summary>
/// <c>POST /oauth/v1/par</c> (RFC 9126, D40 to D43). The client authenticates as at <c>/token</c>, then
/// <see cref="AuthorizationService.PushAsync"/> runs the checks of <c>/authorize</c> and stores the request.
/// </summary>
public sealed class PushedAuthorization
{
    public const string Path = "/oauth/v1/par";

    private readonly ClientAuthenticator _authenticator;
    private readonly DpopTokenCheck _dpop;
    private readonly AuthorizationService _authorization;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public PushedAuthorization(
        ClientAuthenticator authenticator,
        DpopTokenCheck dpop,
        AuthorizationService authorization,
        IAuditLog audit,
        TimeProvider time)
    {
        _authenticator = authenticator;
        _dpop = dpop;
        _authorization = authorization;
        _audit = audit;
        _time = time;
    }

    public async Task<Result<PushedRequest>> PushAsync(RequestContext context, PushRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        // D40: a confidential client proves itself with its secret, a public client names itself (RFC 9126, section 2).
        // PAR stops a change of the parameters in the browser for both. Only the confidential one is authenticated.
        var authentication = await _authenticator
            .AuthenticateAsync(context.Tenant.Id, context.Issuer, request.ClientId, request.ClientSecret, request.ClientAssertion, cancellationToken)
            .ConfigureAwait(false);
        if (!authentication.IsSuccess)
        {
            // Audited like a failed authentication at /token, so /par is no secret-guessing door.
            await _audit.WriteAsync(
                AuditEvent.Record(
                    Guid.CreateVersion7(),
                    context.Tenant.Id,
                    AuditEventTypes.PushRefused,
                    context.CorrelationId,
                    _time.GetUtcNow(),
                    context.SourceIp,
                    data: new Dictionary<string, string>
                    {
                        ["client_id"] = request.ClientId is { Length: > 128 } id ? id[..128] : request.ClientId ?? string.Empty,
                        ["error"] = authentication.Error.Code,
                        ["reason"] = authentication.Error.AuditDetail,
                    }),
                cancellationToken).ConfigureAwait(false);
            return Result.Failure<PushedRequest>(authentication.Error);
        }

        // RFC 9449, section 10.1: a proof at PAR binds the code to its key. It is optional, also for require_dpop.
        string? proofKey = null;
        if (request.DpopProof is { } proof)
        {
            var checkedProof = await _dpop.CheckProofAsync(context, proof, new Uri(context.Issuer + Path), cancellationToken).ConfigureAwait(false);
            if (!checkedProof.IsSuccess)
            {
                return Result.Failure<PushedRequest>(checkedProof.Error);
            }

            proofKey = checkedProof.Value;
        }

        return await _authorization.PushAsync(context, authentication.Value, request.Parameters, proofKey, cancellationToken).ConfigureAwait(false);
    }
}
