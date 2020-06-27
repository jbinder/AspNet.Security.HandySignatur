using System;

namespace AspNet.Security.HandySignatur
{
    public static class HandySignaturAuthenticationDefaultViews
    {
        public static Func<HandySignaturAuthenticationOptions, string, string> RedirectToAtrustViewCreator = (options, dataUrl) =>
            $@"
            Loading... please wait.
            <script>window.onload = function(){{document.forms['form'].submit();}}</script>
            <form id='form' action='https://www.a-trust.at/mobile/https-security-layer-request/default.aspx' enctype='application/x-www-form-urlencoded' method='post'>
                <input name='XMLRequest' type='hidden' value=""<?xml version='1.0' encoding='UTF-8'?>
                    <sl:InfoboxReadRequest xmlns:sl='http://www.buergerkarte.at/namespaces/securitylayer/1.2#'>
                        <sl:InfoboxIdentifier>IdentityLink</sl:InfoboxIdentifier>
                        <sl:BinaryFileParameters ContentIsXMLEntity='true'/>
                        <sl:BoxSpecificParameters>
                            <sl:IdentityLinkDomainIdentifier>{options.IdentityLinkDomainIdentifier}</sl:IdentityLinkDomainIdentifier>
                        </sl:BoxSpecificParameters>
                    </sl:InfoboxReadRequest>"" />
                <input type='hidden' name='DataURL' value='{dataUrl}' />
                <!--<input type='submit' value='Weiter zu a-trust!'>-->
            </form>
            ";

        public static Func<string, string, string, string> RedirectFromAtrustViewCreator = (targetUrl, xmlResponse, responseType) =>
            $@"
            Loading... please wait.
            <form id='form' action='{targetUrl}' enctype='application/x-www-form-urlencoded' method='post'>
                <input name='XMLResponse' type='hidden' value=""{xmlResponse}"" />
                <input type='hidden' name='ResponseType' value='{responseType}' />
                <!--<input type='submit' value='Zurück zur app!'>-->
            </form>
            <script>window.onload = function(){{document.forms['form'].submit();}}</script>
            ";
    }
}
