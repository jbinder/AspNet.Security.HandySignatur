using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Xml;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.HandySignatur
{
    /// <summary>
    /// This is based on <see href="https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/blob/rel/2.1.0/src/AspNet.Security.OpenId/OpenIdAuthenticationHandler.cs" />.
    /// </summary>
    /// <typeparam name="TOptions"></typeparam>
    public class HandySignaturAuthenticationHandler<TOptions> : RemoteAuthenticationHandler<TOptions>
        where TOptions : HandySignaturAuthenticationOptions, new()
    {
        public HandySignaturAuthenticationHandler(
            [NotNull] IOptionsMonitor<TOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// Customized to breakout from the A-Trust environment, <see cref="HandySignaturAuthenticationOptions.PreCallbackPath"/>.
        /// </summary>
        /// <returns></returns>
        public override async Task<bool> HandleRequestAsync()
        {
            if (Request.Path != Options.PreCallbackPath) return await base.HandleRequestAsync();

            var response = await Request.ReadFormAsync(Context.RequestAborted);
            var xmlResponse = response["XMLResponse"].ToString().Replace('"', '\'');
            var responseType = response["ResponseType"].ToString().Replace('"', '\'');
            var targetUrl = Request.GetEncodedUrl().Replace(Options.PreCallbackPath, Options.CallbackPath);

            var form = Options.RedirectFromAtrustViewCreator(targetUrl, xmlResponse, responseType);

            SetResponse(form);

            return true;
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                return HandleRequestResult.Fail("The authentication response was rejected because it was made " +
                                                "using an invalid method: make sure to use either GET or POST.");
            }

            // Always extract the "state" parameter from the query string.
            var state = Request.Query[HandySignaturAuthenticationConstants.Parameters.State];
            if (string.IsNullOrEmpty(state))
            {
                return HandleRequestResult.Fail("The authentication response was rejected " +
                                                "because the state parameter was missing.");
            }

            var properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null)
            {
                return HandleRequestResult.Fail("The authentication response was rejected " +
                                                "because the state parameter was invalid.");
            }

            // Validate the anti-forgery token
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("The authentication response was rejected " +
                                                "because the anti-forgery token was invalid.");
            }

            // TODO: validate the signature

            var form = await Request.ReadFormAsync(Context.RequestAborted);

            var xmlDoc = new XmlDocument {PreserveWhitespace = true};
            ClaimsIdentity identity;
            try
            {
                xmlDoc.LoadXml(form["XMLResponse"]);
                identity = CreateClaimsIdentityFromXml(xmlDoc);
            } catch (Exception e)
            {
                return HandleRequestResult.Fail("The authentication response was rejected because " +
                                                $"the XMLResponse is invalid: {e.Message}");
            }

            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);

            return HandleRequestResult.Success(ticket);
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Use the current address as the final location where the user agent
            // will be redirected to if one has not been explicitly provided.
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = Request.Scheme + "://" + Request.Host +
                                         OriginalPathBase + Request.Path + Request.QueryString;
            }
            else
            {
                // Use an absolute url, as the redirectUri be rendered in the context of A-Trust instead being redirected
                properties.RedirectUri = Request.Scheme + "://" + Request.Host + properties.RedirectUri;
            }

            GenerateCorrelationId(properties);

            // Only Https is accepted
            var redirectUri = QueryHelpers.AddQueryString("https://" + Request.Host + Options.PreCallbackPath, new Dictionary<string, string>
            {
                {HandySignaturAuthenticationConstants.Parameters.State, Options.StateDataFormat.Protect(properties)}
            });

            var form = Options.RedirectToAtrustViewCreator(Options, redirectUri);
            SetResponse(form);
            return Task.CompletedTask;
        }

        private void SetResponse(string html)
        {
            Response.ContentType = "text/html";
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(html)))
            {
                stream.CopyTo(Response.Body);
            }
        }

        private ClaimsIdentity CreateClaimsIdentityFromXml(XmlDocument xmlDoc)
        {
            var firstName = xmlDoc.GetElementsByTagName("pr:GivenName")[0].InnerText;
            var lastName = xmlDoc.GetElementsByTagName("pr:FamilyName")[0].InnerText;
            var dateOfBirth = xmlDoc.GetElementsByTagName("pr:DateOfBirth")[0].InnerText;
            var id = xmlDoc.GetElementsByTagName("pr:Value")[0].InnerText;

            var identity = new ClaimsIdentity(Scheme.Name);

            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, id, ClaimValueTypes.String, Options.ClaimsIssuer));
            identity.AddClaim(new Claim(ClaimTypes.GivenName, firstName, ClaimValueTypes.String, Options.ClaimsIssuer));
            identity.AddClaim(new Claim(ClaimTypes.Surname, lastName, ClaimValueTypes.String, Options.ClaimsIssuer));
            identity.AddClaim(new Claim(ClaimTypes.Name, $"{firstName} {lastName}", ClaimValueTypes.String,
                Options.ClaimsIssuer));
            identity.AddClaim(new Claim(ClaimTypes.DateOfBirth, dateOfBirth, ClaimValueTypes.String, Options.ClaimsIssuer));
            return identity;
        }
    }
}
