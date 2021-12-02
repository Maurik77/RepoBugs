using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace WebApplication1
{
    public class HermodrAuthenticationHandler : AuthenticationHandler<HermodrAuthenticationSchemeOptions>
    {
        protected override string ResolveTarget(string scheme)
        {
            return base.ResolveTarget(scheme);
        }

        public HermodrAuthenticationHandler(IOptionsMonitor<HermodrAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {

        }

        public static string SchemeName => "Hermodr";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // Simplfied logic to repro problem

            var identity = new ClaimsIdentity();
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "User"));
            identity.AddClaim(new Claim(ClaimTypes.Role, "Users"));

            var principal = new ClaimsPrincipal(identity);

            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));

        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            return base.HandleChallengeAsync(properties);
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            return base.HandleForbiddenAsync(properties);
        }
    }

    public class HermodrAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
    }
}
