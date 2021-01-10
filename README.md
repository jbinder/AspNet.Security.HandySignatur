# AspNet.Security.HandySignatur

Handy-Signatur [1] authentication provider for ASP.NET Core 2.1 [2].

:warning: Alpha, do not use in production!


## Usage

Install the NuGet package:

    PM> Install-Package AspNet.Security.HandySignatur -Version 2.1.0-alpha.2

Adapt your `Startup` class to include the following:

    public void ConfigureServices(IServiceCollection services)
    {
        // ...
        services.AddAuthentication()
            .AddHandySignatur(options => { options.IdentityLinkDomainIdentifier = "TODO"; });
        // ...
    }

    public void Configure(IApplicationBuilder app, IHostingEnvironment env)
    {
        // ...
        app.UseAuthentication();
        // ...
    }

where the `IdentityLinkDomainIdentifier` is the identifier of the requesting authority in the private sector encoded as URN, see [3].

The following claims are available:

* NameIdentifier
* GivenName
* Surname
* Name
* DateOfBirth

To customize the redirect views, the `RedirectToAtrustViewCreator` and `RedirectFromAtrustViewCreator` options can be used.


## References

[1] https://www.handy-signatur.at/

[2] https://docs.microsoft.com/en-us/aspnet/core/?view=aspnetcore-2.1

[3] https://www.buergerkarte.at/konzept/securitylayer/spezifikation/20080220/tutorial/tutorial.html

