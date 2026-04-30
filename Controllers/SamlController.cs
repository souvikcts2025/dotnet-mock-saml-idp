using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Encodings.Web;
using System.Xml;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens.Saml2;
using MockSamlIdp.Models;
using MockSamlIdp.Services;

namespace MockSamlIdp.Controllers;

public class SamlController : Controller
{
    private readonly Saml2Configuration _idpConfig;
    private readonly UserStore _users;
    private readonly IConfiguration _configuration;

    public SamlController(Saml2Configuration idpConfig, UserStore users, IConfiguration configuration)
    {
        _idpConfig = idpConfig;
        _users = users;
        _configuration = configuration;
    }

    [HttpGet("saml/metadata")]
    public IActionResult Metadata()
    {
        var entityDescriptor = new EntityDescriptor(_idpConfig);
        entityDescriptor.ValidUntil = 365;
        entityDescriptor.IdPSsoDescriptor = new IdPSsoDescriptor
        {
            WantAuthnRequestsSigned = false,
            SigningCertificates = new[] { _idpConfig.SigningCertificate },
            SingleSignOnServices = new[]
            {
                new SingleSignOnService
                {
                    Binding = ProtocolBindings.HttpPost,
                    Location = new Uri(Url.ActionLink("Login", "Saml")!)
                },
                new SingleSignOnService
                {
                    Binding = ProtocolBindings.HttpRedirect,
                    Location = new Uri(Url.ActionLink("Login", "Saml")!)
                }
            },
            SingleLogoutServices = new[]
            {
                new SingleLogoutService
                {
                    Binding = ProtocolBindings.HttpRedirect,
                    Location = new Uri(Url.ActionLink("Logout", "Saml")!)
                }
            },
            NameIDFormats = new[] { NameIdentifierFormats.Email }
        };
        return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
    }

    [HttpGet("saml/logout")]
    [HttpPost("saml/logout")]
    public IActionResult Logout()
    {
        try
        {
            var logoutRequest = new Saml2LogoutRequest(_idpConfig);
            string? relayState;

            if (Request.Method == HttpMethods.Get)
            {
                var binding = new Saml2RedirectBinding();
                binding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);
                relayState = binding.RelayState;
            }
            else
            {
                var binding = new Saml2PostBinding();
                binding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);
                relayState = binding.RelayState;
            }

            var spSloUrl = _configuration["Saml2:SpSloResponseUrl"];
            if (string.IsNullOrWhiteSpace(spSloUrl))
                return Content("Logout received. Set Saml2:SpSloResponseUrl in appsettings.json to enable IdP→SP LogoutResponse redirect.", "text/plain");

            var logoutResponse = new Saml2LogoutResponse(_idpConfig)
            {
                InResponseTo = logoutRequest.Id,
                Status = Saml2StatusCodes.Success,
                Destination = new Uri(spSloUrl)
            };

            var responseBinding = new Saml2RedirectBinding { RelayState = relayState };
            responseBinding.Bind(logoutResponse);
            return responseBinding.ToActionResult();
        }
        catch (Exception ex)
        {
            return BadRequest($"SLO request processing failed: {ex.Message}");
        }
    }

    [HttpGet("saml/login")]
    [HttpPost("saml/login")]
    public IActionResult Login()
    {
        try
        {
            var authnRequest = new Saml2AuthnRequest(_idpConfig);
            string relayState;

            if (Request.Method == HttpMethods.Get)
            {
                var binding = new Saml2RedirectBinding();
                binding.Unbind(Request.ToGenericHttpRequest(), authnRequest);
                relayState = binding.RelayState ?? string.Empty;
            }
            else
            {
                var binding = new Saml2PostBinding();
                binding.Unbind(Request.ToGenericHttpRequest(), authnRequest);
                relayState = binding.RelayState ?? string.Empty;
            }

            TempData["InResponseTo"] = authnRequest.Id?.Value;
            TempData["RelayState"] = relayState;
            TempData["AssertionConsumerServiceUrl"] = authnRequest.AssertionConsumerServiceUrl?.AbsoluteUri;
            TempData["SpIssuer"] = authnRequest.Issuer;
        }
        catch
        {
            // Allow direct browser access when no SAMLRequest is present
        }

        return View(new LoginViewModel());
    }

    [HttpPost("saml/login-submit")]
    [ValidateAntiForgeryToken]
    public IActionResult LoginSubmit(LoginViewModel model)
    {
        if (!ModelState.IsValid)
            return View("Login", model);

        var user = _users.Validate(model.Email, model.Password);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View("Login", model);
        }

        var inResponseTo = TempData["InResponseTo"]?.ToString();
        var relayState = TempData["RelayState"]?.ToString();
        var acsUrl = TempData["AssertionConsumerServiceUrl"]?.ToString();
        var spIssuer = TempData["SpIssuer"]?.ToString();

        if (string.IsNullOrEmpty(acsUrl))
            return BadRequest("Missing ACS URL — start the SSO flow from your application.");

        var responseXml = BuildSamlResponseXml(user, inResponseTo, acsUrl, spIssuer);
        var responseB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(responseXml));

        var encodedAcs = HtmlEncoder.Default.Encode(acsUrl);
        var relayStateInput = string.IsNullOrEmpty(relayState)
            ? ""
            : $"<input type=\"hidden\" name=\"RelayState\" value=\"{HtmlEncoder.Default.Encode(relayState)}\"/>";

        var html = $"""
            <!DOCTYPE html>
            <html><body onload="document.forms[0].submit()">
            <form method="POST" action="{encodedAcs}">
              <input type="hidden" name="SAMLResponse" value="{responseB64}"/>
              {relayStateInput}
              <noscript><button type="submit">Continue</button></noscript>
            </form>
            </body></html>
            """;

        return Content(html, "text/html");
    }

    private string BuildSamlResponseXml(MockUser user, string? inResponseTo, string acsUrl, string? spIssuer)
    {
        var now = DateTime.UtcNow;
        var issuer = _idpConfig.Issuer;
        var assertionId = "_" + Guid.NewGuid().ToString("N");
        var responseId = "_" + Guid.NewGuid().ToString("N");
        var audience = string.IsNullOrEmpty(spIssuer) ? issuer : spIssuer;

        var notBefore = now.AddMinutes(-2);
        var notOnOrAfter = now.AddMinutes(10);
        var subjectNotOnOrAfter = now.AddMinutes(10);

        var inRespToAttr = string.IsNullOrEmpty(inResponseTo)
            ? ""
            : $" InResponseTo=\"{XmlEscape(inResponseTo)}\"";

        var xml = $"""
            <samlp:Response
              xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
              ID="{responseId}"
              Version="2.0"
              IssueInstant="{Iso(now)}"
              Destination="{XmlEscape(acsUrl)}"{inRespToAttr}>
              <saml:Issuer>{XmlEscape(issuer)}</saml:Issuer>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
              <saml:Assertion
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{assertionId}"
                Version="2.0"
                IssueInstant="{Iso(now)}">
                <saml:Issuer>{XmlEscape(issuer)}</saml:Issuer>
                <saml:Subject>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{XmlEscape(user.Email)}</saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData
                      NotOnOrAfter="{Iso(subjectNotOnOrAfter)}"
                      Recipient="{XmlEscape(acsUrl)}"{inRespToAttr}/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="{Iso(notBefore)}" NotOnOrAfter="{Iso(notOnOrAfter)}">
                  <saml:AudienceRestriction>
                    <saml:Audience>{XmlEscape(audience)}</saml:Audience>
                  </saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="{Iso(now)}">
                  <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                  </saml:AuthnContext>
                </saml:AuthnStatement>
                <saml:AttributeStatement>
                  <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                                  NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml:AttributeValue>{XmlEscape(user.Email)}</saml:AttributeValue>
                  </saml:Attribute>
                  <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
                                  NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml:AttributeValue>{XmlEscape(user.DisplayName)}</saml:AttributeValue>
                  </saml:Attribute>
                  <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
                                  NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml:AttributeValue>{XmlEscape(user.Email)}</saml:AttributeValue>
                  </saml:Attribute>
                </saml:AttributeStatement>
              </saml:Assertion>
            </samlp:Response>
            """;

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);

        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        // Sign assertion first (inner), then response (outer)
        var assertionEl = (XmlElement)doc.SelectSingleNode("//saml:Assertion", nsm)!;
        SignElement(doc, assertionEl, assertionId);
        SignElement(doc, doc.DocumentElement!, responseId);

        return doc.OuterXml;
    }

    private void SignElement(XmlDocument doc, XmlElement element, string elementId)
    {
        var cert = _idpConfig.SigningCertificate;
        using var rsa = cert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Signing certificate does not contain a private key.");

        var signedXml = new SamlSignedXml(doc);
        signedXml.SigningKey = rsa;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

        var reference = new Reference("#" + elementId);
        reference.DigestMethod = SignedXml.XmlDsigSHA256Url;
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();
        var sigEl = signedXml.GetXml();

        // Insert <ds:Signature> immediately after <saml:Issuer>
        var issuerNode = element.ChildNodes
            .Cast<XmlNode>()
            .FirstOrDefault(n => n.LocalName == "Issuer");

        var importedSig = doc.ImportNode(sigEl, true);
        if (issuerNode != null)
            element.InsertAfter(importedSig, issuerNode);
        else
            element.PrependChild(importedSig);
    }

    private static string XmlEscape(string value) =>
        value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    // Formats a UTC DateTime as strict ISO 8601 with Z suffix, invariant culture,
    // with T and Z quoted so they are never reinterpreted as format specifiers.
    private static string Iso(DateTime dt) =>
        dt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH':'mm':'ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    // SignedXml.GetIdElement only looks for id/Id/ID defined as xml:id type.
    // SAML uses ID="..." as a plain attribute, so we override the lookup.
    private sealed class SamlSignedXml : SignedXml
    {
        public SamlSignedXml(XmlDocument doc) : base(doc) { }

        public override XmlElement? GetIdElement(XmlDocument document, string idValue)
        {
            var elem = base.GetIdElement(document, idValue);
            if (elem != null) return elem;
            return document.SelectSingleNode($"//*[@ID='{idValue}']") as XmlElement;
        }
    }
}
