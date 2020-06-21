using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AspNet.Security.HandySignatur
{
    /// <summary>
    /// This is based upon <see href="https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/blob/rel/2.1.0/src/AspNet.Security.OpenId.Steam/SteamAuthenticationExtensions.cs"/>.
    /// </summary>
    public static class HandySignaturAuthenticationExtensions
    {
        /// <summary>
        /// Adds <see cref="HandySignaturAuthenticationHandler{TOptions}"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables HandySignatur authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the HandySignatur options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddHandySignatur(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<HandySignaturAuthenticationOptions> configuration)
        {
            return builder.AddHandySignatur<HandySignaturAuthenticationOptions, HandySignaturAuthenticationHandler<HandySignaturAuthenticationOptions>>(HandySignaturAuthenticationDefaults.AuthenticationScheme, HandySignaturAuthenticationDefaults.DisplayName, configuration);
        }

        /// <summary>
        /// Adds <see cref="HandySignaturAuthenticationHandler{TOptions}"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables HandySignatur authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="caption">The optional display name associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the HandySignatur options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddHandySignatur<TOptions, THandler>(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme, [CanBeNull] string caption,
            [NotNull] Action<HandySignaturAuthenticationOptions> configuration)
            where TOptions : HandySignaturAuthenticationOptions, new()
            where THandler : HandySignaturAuthenticationHandler<TOptions>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (string.IsNullOrEmpty(scheme))
            {
                throw new ArgumentException("The scheme cannot be null or empty.", nameof(scheme));
            }

            // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, HandySignaturAuthenticationInitializer<TOptions, THandler>>());

            return builder.AddRemoteScheme<TOptions, THandler>(scheme, caption, configuration);
        }
    }
}
