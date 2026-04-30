# Mock SAML 2.0 IdP

A local mock Identity Provider (IdP) that simulates Microsoft Entra ID's SAML 2.0 SSO flow. Built with .NET 8.

Intended for development and testing of applications that use SAML 2.0 authentication (e.g. apps integrating with Sustainsys.Saml2 or migrating from Windows Auth to Entra ID SSO) when the real Entra ID tenant is not yet available.

---

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8)
- No Docker, no admin rights needed

---

## Running

```bash
dotnet run --project MockSamlIdp.csproj --launch-profile http
```

The IdP will be available at `http://localhost:5001`.

| Endpoint | URL |
|---|---|
| Metadata | `http://localhost:5001/saml/metadata` |
| SSO (login) | `http://localhost:5001/saml/login` |
| SLO (logout) | `http://localhost:5001/saml/logout` |

---

## Test users

Defined in `users.json`. Edit this file to add or change users — no recompile needed (file is read on startup).

| Email | Password | Display Name |
|---|---|---|
| bob@example.com | bob | Bob Smith |
| alice@example.com | alice | Alice Jones |

### Adding a user

```json
{
  "email": "charlie@company.com",
  "password": "charlie",
  "displayName": "Charlie Brown",
  "objectId": "aaaaaaaa-0000-0000-0000-000000000003"
}
```

`objectId` can be any unique GUID. It is emitted as the `objectidentifier` claim to mimic Entra ID.

---

## SAML response structure

The IdP issues a fully signed SAML 2.0 response containing a complete `<saml:Assertion>`:

- **Outer `<samlp:Response>`** — signed with the IdP private key (RSA-SHA256)
- **Inner `<saml:Assertion>`** — also individually signed with the IdP private key
- **`<saml:Subject>`** — `<saml:NameID>` set to the user's email, format `emailAddress`
- **`<saml:SubjectConfirmation Method="bearer">`** — includes `Recipient` (ACS URL) and `InResponseTo` (AuthnRequest ID)
- **`<saml:Conditions>`** — `NotBefore` (2 min in past) and `NotOnOrAfter` (10 min ahead), with `<saml:AudienceRestriction>` set to the SP entity ID
- **`<saml:AuthnStatement>`** — `AuthnContextClassRef` = `urn:oasis:names:tc:SAML:2.0:ac:classes:Password`
- **`<saml:AttributeStatement>`** — see claims table below

All datetime attributes use strict ISO 8601 UTC format: `yyyy-MM-ddTHH:mm:ssZ`.

---

## Claims emitted

| Claim URI | Value |
|---|---|
| `…/claims/emailaddress` | user's email |
| `…/claims/upn` | user's email |
| `…/claims/name` | user's display name |
| `…/claims/nameidentifier` | user's email |
| `…/identity/claims/objectidentifier` | per-user GUID from `users.json` |
| `…/identity/claims/tenantid` | fixed fake GUID `bbbbbbbb-0000-0000-0000-000000000000` |
| `…/identity/claims/authenticationmethod` | `PasswordProtectedTransport` |

---

## Configuring a .NET SP (Sustainsys.Saml2)

### ASP.NET Core

```csharp
builder.Services.AddAuthentication().AddSaml2(options =>
{
    options.SPOptions.EntityId = new EntityId("http://localhost:5000");
    options.IdentityProviders.Add(new IdentityProvider(
        new EntityId("http://localhost:5001/saml/metadata"),
        options.SPOptions)
    {
        MetadataLocation = "http://localhost:5001/saml/metadata",
        LoadMetadata = true
    });
});
```

### ASP.NET 4.x (`web.config`)

Install:
```
Install-Package Sustainsys.Saml2.HttpModule
```

```xml
<sustainsys.saml2 entityId="http://your-app/saml2" returnUrl="http://your-app/">
  <identityProviders>
    <add entityId="http://localhost:5001/saml/metadata"
         metadataLocation="http://localhost:5001/saml/metadata"
         allowUnsolicitedAuthnResponse="false"
         binding="HttpRedirect" />
  </identityProviders>
</sustainsys.saml2>

<authentication mode="Forms">
  <forms loginUrl="~/Saml2/SignIn" timeout="60" />
</authentication>
```

---

## Certificate

`idp.pfx` is a self-signed certificate checked into the repo (password: `MockIdp123!`). It is intentionally committed — this is a development-only mock, not a production secret.

To regenerate it:
```powershell
$cert = New-SelfSignedCertificate -Subject 'CN=MockSamlIdp' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(10)
$pwd = ConvertTo-SecureString -String 'MockIdp123!' -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath 'idp.pfx' -Password $pwd
```
