using PidrobitOK.AuthService.Models;
using System.Security.Claims;

namespace PidrobitOK.AuthService.Services
{
    public interface IJwtTokenService
    {
        Task<string> GenerateAccessToken(PidrobitokUser user);
        string GenerateRefreshToken();
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}
