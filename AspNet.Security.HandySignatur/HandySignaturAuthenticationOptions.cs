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

        public HandySignaturAuthenticationOptions()
        {
            CallbackPath = HandySignaturAuthenticationDefaults.CallbackPath;
            PreCallbackPath = HandySignaturAuthenticationDefaults.PreCallbackPath;
        }
    }
}
