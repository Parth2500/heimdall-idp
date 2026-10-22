using Heimdall.Application.Common;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Clients;

namespace Heimdall.Application.Dpop;

/// <summary>
/// The DPoP step of a token request (D24 to D26). A grant runs it after every check that needs no database, because
/// the replay check is a database write.
/// </summary>
public sealed class DpopTokenCheck
{
    private readonly IDpopProofValidator _validator;
    private readonly IDpopReplayStore _replay;

    public DpopTokenCheck(IDpopProofValidator validator, IDpopReplayStore replay)
    {
        _validator = validator;
        _replay = replay;
    }

    /// <param name="proof">The DPoP header, or null when the request has none.</param>
    /// <returns>
    /// The key thumbprint to bind the tokens to; null when the request has no proof and the client does not require one;
    /// or <c>invalid_dpop_proof</c>.
    /// </returns>
    public async Task<Result<string?>> CheckAsync(RequestContext context, Client client, string? proof, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(client);

        if (proof is null)
        {
            return client.RequireDpop
                ? Result.Failure<string?>(OAuthError.InvalidDpopProof("client requires DPoP"))
                : Result.Success<string?>(null);
        }

        var checkedProof = _validator.Validate(proof, new DpopRequest("POST", TokenEndpointAddress.For(context.Issuer)));
        if (!checkedProof.IsSuccess)
        {
            return Result.Failure<string?>(checkedProof.Error);
        }

        if (!await _replay.TryUseAsync(context.Tenant.Id, checkedProof.Value, cancellationToken).ConfigureAwait(false))
        {
            return Result.Failure<string?>(OAuthError.InvalidDpopProof("proof replayed"));
        }

        return Result.Success<string?>(checkedProof.Value.KeyThumbprint);
    }
}
