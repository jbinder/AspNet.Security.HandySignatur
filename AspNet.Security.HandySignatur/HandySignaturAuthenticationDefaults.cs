namespace AspNet.Security.HandySignatur
{
    /// <summary>
    /// Based upon <see href="https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/blob/rel/2.1.0/src/AspNet.Security.OpenId/OpenIdAuthenticationDefaults.cs" />.
    /// </summary>
    public static class HandySignaturAuthenticationDefaults
    {
        /// <summary>
        /// Gets the default value associated with <see cref="AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = "HandySignatur";

        /// <summary>
        /// Gets the default value associated with <see cref="AuthenticationScheme.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "Handy-Signatur";

        /// <summary>
        /// Gets the default value associated with <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-handysignatur";

        /// <summary>
        /// Gets the default value associated with <see cref="HandySignaturAuthenticationOptions.PreCallbackPath"/>.
        /// </summary>
        public const string PreCallbackPath = "/signin-handysignatur-pre";
    }
}
