using System;
using System.Net.Http;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace AspNet.Security.HandySignatur
{
    /// <summary>
    /// This is based upon <see href="https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/blob/rel/2.1.0/src/AspNet.Security.OpenId/OpenIdAuthenticationInitializer.cs" />.
    /// </summary>
    public class HandySignaturAuthenticationInitializer<TOptions, THandler> : IPostConfigureOptions<TOptions>
        where TOptions : HandySignaturAuthenticationOptions, new()
        where THandler : HandySignaturAuthenticationHandler<TOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        public HandySignaturAuthenticationInitializer([NotNull] IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        public void PostConfigure(string name, TOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(options.IdentityLinkDomainIdentifier))
            {

                throw new ArgumentException("The IdentityLinkDomainIdentifier cannot be null or empty.", nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            if (options.RedirectToAtrustViewCreator == null)
            {
                throw new ArgumentException("The RedirectToAtrustViewCreator cannot be null.", nameof(options));
            }

            if (options.RedirectFromAtrustViewCreator == null)
            {
                throw new ArgumentException("The RedirectFromAtrustViewCreator cannot be null.", nameof(options));
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = _dataProtectionProvider;
            }

            if (options.StateDataFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    nameof(HandySignaturAuthenticationHandler<HandySignaturAuthenticationOptions>));
                options.StateDataFormat = new PropertiesDataFormat(protector);
            }

            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET Core HandySignatur middleware");
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }
        }
    }
}
