using System.Text.Json;
using MockSamlIdp.Models;

namespace MockSamlIdp.Services;

public class UserStore
{
    private readonly List<MockUser> _users;

    public UserStore(IWebHostEnvironment env)
    {
        var path = Path.Combine(env.ContentRootPath, "users.json");
        var json = File.ReadAllText(path);
        _users = JsonSerializer.Deserialize<List<MockUser>>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? new List<MockUser>();
    }

    public MockUser? Validate(string email, string password)
        => _users.FirstOrDefault(u =>
            string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)
            && u.Password == password);
}
