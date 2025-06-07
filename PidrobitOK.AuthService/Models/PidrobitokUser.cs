using Microsoft.AspNetCore.Identity;

namespace PidrobitOK.AuthService.Models
{
    public class PidrobitokUser : IdentityUser<Guid>
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }

        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
    }
}