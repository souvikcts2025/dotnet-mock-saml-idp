using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using MockSamlIdp.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddAntiforgery();

// Register UserStore (reads users.json)
builder.Services.AddSingleton<UserStore>();

// Configure ITfoxtec Saml2Configuration for the IdP role
var samlSection = builder.Configuration.GetSection("Saml2");
var certPath = Path.Combine(builder.Environment.ContentRootPath, samlSection["CertificatePath"]!);
var certPassword = samlSection["CertificatePassword"]!;

var idpConfig = new Saml2Configuration
{
    Issuer = samlSection["IdPEntityId"]!,
    SigningCertificate = new X509Certificate2(certPath, certPassword),
    SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
    RevocationMode = X509RevocationMode.NoCheck
};
idpConfig.SignatureValidationCertificates.Add(idpConfig.SigningCertificate);

var sloUrl = samlSection["SingleLogoutUrl"];
if (!string.IsNullOrEmpty(sloUrl))
    idpConfig.SingleLogoutDestination = new Uri(sloUrl);

builder.Services.AddSingleton(idpConfig);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAntiforgery();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
