using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.HandySignatur
{
    public class HandySignaturAuthenticationOptions : RemoteAuthenticationOptions
    {
        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// <see cref="HandySignaturAuthenticationHandler{TOptions}"/> performs the redirect to the regular
        /// <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// This is just used to breakout from the A-Trust environment, i.e. to be able to set our authentication cookies.
        /// </summary>
        public PathString PreCallbackPath { get; set; }

        /// <summary>
        /// Identifier of the requesting authority in the private sector encoded as URN. See
        /// <see href="https://www.buergerkarte.at/konzept/securitylayer/spezifikation/20080220/tutorial/tutorial.html">Tutorium zur österreichischen Bürgerkarte</see>
        /// for further information.
        /// </summary>
        public string IdentityLinkDomainIdentifier { get; set; }

        /// <summary>
        /// Generates the view which performs the redirect to A-Trust login page, see <see cref="HandySignaturAuthenticationDefaultViews.RedirectToAtrustViewCreator" />.
        /// </summary>
        public Func<HandySignaturAuthenticationOptions, string, string> RedirectToAtrustViewCreator { get; set; }

        /// <summary>
        /// Generates the view which performs the redirect back from A-Trust, see <see cref="HandySignaturAuthenticationDefaultViews.RedirectFromAtrustViewCreator" />.
        /// </summary>
        public Func<string, string, string, string> RedirectFromAtrustViewCreator { get; set; }

        /// <summary>
        /// Gets or sets the data format used to serialize the
        /// authentication properties used for the "state" parameter.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public HandySignaturAuthenticationOptions()
        {
            CallbackPath = HandySignaturAuthenticationDefaults.CallbackPath;
            PreCallbackPath = HandySignaturAuthenticationDefaults.PreCallbackPath;
            RedirectToAtrustViewCreator = HandySignaturAuthenticationDefaultViews.RedirectToAtrustViewCreator;
            RedirectFromAtrustViewCreator = HandySignaturAuthenticationDefaultViews.RedirectFromAtrustViewCreator;
        }
    }
}
