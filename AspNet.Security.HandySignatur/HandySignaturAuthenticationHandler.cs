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

            // Validate the anti-forgery token
            var items = new Dictionary<string, string> {{"LoginProvider", "HandySignatur"}, {".xsrf", Request.Query["cid"]} };
            var properties = new AuthenticationProperties(items);
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
            properties.RedirectUri = Encoding.UTF8.GetString(Convert.FromBase64String(Request.Query["redirect_uri"].ToString().Replace('-', '+').Replace('_', '/')));
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

            GenerateCorrelationId(properties);

            var encodedRedirectUri = Convert.ToBase64String(Encoding.UTF8.GetBytes(Request.Scheme + "://" + Request.Host + properties.RedirectUri)).Replace('+', '-').Replace('/', '_');
            var dataUrl = "https://" + Request.Host + Options.PreCallbackPath + "?redirect_uri=" + encodedRedirectUri + $"&cid={properties.Items[".xsrf"]}"; // only HTTPS is accepted

            var form = Options.RedirectToAtrustViewCreator(Options, dataUrl);
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
