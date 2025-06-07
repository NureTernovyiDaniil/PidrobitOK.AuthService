using Moq;
using PidrobitOK.AuthService.Models;
using PidrobitOK.AuthService.Options;
using PidrobitOK.AuthService.Services;
using PidrobitOK.AuthService_Test.Helpers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace PidrobitOK.AuthService_Test.Integrations
{
    public class IdentityIntegrationTests
    {
        [Fact]
        public async void GenerateAccessToken_ShouldReturnValidToken()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "test@example.com"
            };

            var jwtService = MockHelper.MockJwtTokenService().Object;

            var token = await jwtService.GenerateAccessToken(user);

            Assert.False(string.IsNullOrWhiteSpace(token));
        }

        [Fact]
        public void GenerateRefreshToken_ShouldReturn64ByteBase64Token()
        {
            var jwtOptions = new JwtSettings()
            {
                Secret = "supersecretkeysupersecretkey123!",
                Issuer = "issuer",
                Audience = "audience",
                TokenLifetimeMin = 60
            };

            var userManagerMock = MockHelper.MockUserManager().Object;
            var jwtService = new JwtTokenService(userManagerMock, jwtOptions);

            var token = jwtService.GenerateRefreshToken();

            var bytes = Convert.FromBase64String(token);
            Assert.Equal(64, bytes.Length);
        }

        [Fact]
        public async Task GetPrincipalFromExpiredToken_ShouldReturnValidPrincipal()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "expired@example.com"
            };

            var jwtOptions = new JwtSettings()
            {
                Issuer = "test-issuer",
                Audience = "test-audience",
                Secret = "supersecretkeysupersecretkey123!",
                TokenLifetimeMin = 1
            };

            var userManagerMock = MockHelper.MockUserManager();
            userManagerMock.Setup(um => um.GetRolesAsync(It.IsAny<PidrobitokUser>()))
                           .ReturnsAsync(new List<string>());

            var jwtService = new JwtTokenService(userManagerMock.Object, jwtOptions);

            var token = await jwtService.GenerateAccessToken(user);

            var principal = jwtService.GetPrincipalFromExpiredToken(token);

            Assert.NotNull(principal);

            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var email = principal.FindFirstValue(ClaimTypes.Email);

            Assert.Equal(user.Id.ToString(), userId);
            Assert.Equal(user.Email, email);
        }

        [Fact]
        public void GetPrincipalFromExpiredToken_ShouldReturnNull_IfTokenIsInvalid()
        {
            var jwtService = MockHelper.MockJwtTokenService();
            var invalidToken = "this.is.not.a.real.token";

            var principal = jwtService.Object.GetPrincipalFromExpiredToken(invalidToken);

            Assert.Null(principal);
        }

        [Fact]
        public async Task GenerateAccessToken_ShouldContainRequiredClaims()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "testclaims@example.com"
            };

            var jwtOptions = new JwtSettings()
            {
                Issuer = "test-issuer",
                Audience = "test-audience",
                Secret = "supersecretkeysupersecretkey123!",
                TokenLifetimeMin = 60
            };

            var userManagerMock = MockHelper.MockUserManager();

            userManagerMock
                .Setup(um => um.GetRolesAsync(It.IsAny<PidrobitokUser>()))
                .ReturnsAsync(new List<string>());

            var jwtService = new JwtTokenService(userManagerMock.Object, jwtOptions);

            var token = await jwtService.GenerateAccessToken(user);

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            var sub = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            var email = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email)?.Value;
            var jti = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

            Assert.Equal(user.Id.ToString(), sub);
            Assert.Equal(user.Email, email);
            Assert.False(string.IsNullOrEmpty(jti));
        }

        [Fact]
        public async Task GetPrincipalFromExpiredToken_ShouldReturnNull_IfSecretIsInvalid()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "broken@example.com"
            };

            var jwtOptions = new JwtSettings()
            {
                Issuer = "test-issuer",
                Audience = "test-audience",
                Secret = "short",
                TokenLifetimeMin = 1
            };

            var userManagerMock = MockHelper.MockUserManager();
            userManagerMock.Setup(um => um.GetRolesAsync(
                It.IsAny<PidrobitokUser>())).ReturnsAsync(new List<string>());

            var jwtService = new JwtTokenService(userManagerMock.Object, jwtOptions);

            string token;

            try
            {
                token = await jwtService.GenerateAccessToken(user);
            }
            catch (ArgumentOutOfRangeException)
            {
                return;
            }

            var principal = jwtService.GetPrincipalFromExpiredToken(token);
            Assert.Null(principal);
        }

        [Fact]
        public void GenerateAccessToken_ShouldGenerateDifferentTokensEachTime()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "repeat@example.com"
            };

            var jwtService = MockHelper.MockJwtTokenService().Object;

            var token1 = jwtService.GenerateAccessToken(user);
            var token2 = jwtService.GenerateAccessToken(user);

            Assert.NotEqual(token1, token2);
        }

        [Fact]
        public void GenerateRefreshToken_ShouldBeUniqueOnEachCall()
        {
            var jwtOptions = new JwtSettings()
            {
                Secret = "supersecretkeysupersecretkey123!",
                Issuer = "issuer",
                Audience = "audience",
                TokenLifetimeMin = 60
            };

            var userManagerMock = MockHelper.MockUserManager().Object;
            var jwtService = new JwtTokenService(userManagerMock, jwtOptions);

            var token1 = jwtService.GenerateRefreshToken();
            var token2 = jwtService.GenerateRefreshToken();

            Assert.NotEqual(token1, token2);
        }

        [Fact]
        public async Task GetPrincipalFromExpiredToken_ShouldReturnNull_IfIssuerIsWrong()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "wrongissuer@example.com"
            };

            var userManagerMock = MockHelper.MockUserManager();
            userManagerMock.Setup(um => um.GetRolesAsync(It.IsAny<PidrobitokUser>()))
                           .ReturnsAsync(new List<string>());

            var jwtOptions = new JwtSettings()
            {
                Issuer = "correct-issuer",
                Audience = "test-audience",
                Secret = "supersecretkeysupersecretkey123!",
                TokenLifetimeMin = 1
            };

            var jwtService = new JwtTokenService(userManagerMock.Object, jwtOptions);
            var token = await jwtService.GenerateAccessToken(user);

            jwtOptions.Issuer = "wrong-issuer";

            var jwtServiceWithWrongIssuer = new JwtTokenService(userManagerMock.Object, jwtOptions);
            var principal = jwtServiceWithWrongIssuer.GetPrincipalFromExpiredToken(token);

            Assert.Null(principal);
        }

        [Fact]
        public async void GetPrincipalFromExpiredToken_ShouldReturnNull_IfTokenIsTampered()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "tampered@example.com"
            };

            var jwtService = MockHelper.MockJwtTokenService().Object;

            var token = await jwtService.GenerateAccessToken(user);
            var tamperedToken = token.Replace('a', 'b');

            var principal = jwtService.GetPrincipalFromExpiredToken(tamperedToken);

            Assert.Null(principal);
        }

        [Fact]
        public async Task GetPrincipalFromExpiredToken_ShouldReturnNull_IfAudienceDoesNotMatch()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "aud@example.com"
            };

            var jwtOptions = new JwtSettings()
            {
                Issuer = "test-issuer",
                Audience = "correct-audience",
                Secret = "supersecretkeysupersecretkey123!",
                TokenLifetimeMin = 1
            };

            var userManagerMock = MockHelper.MockUserManager();
            userManagerMock.Setup(um => um.GetRolesAsync(It.IsAny<PidrobitokUser>()))
                           .ReturnsAsync(new List<string>());

            var jwtService = new JwtTokenService(userManagerMock.Object, jwtOptions);
            var token = await jwtService.GenerateAccessToken(user);

            jwtOptions.Audience = "wrong-audience";

            var jwtServiceWithWrongAudience = new JwtTokenService(userManagerMock.Object, jwtOptions);
            var principal = jwtServiceWithWrongAudience.GetPrincipalFromExpiredToken(token);

            Assert.Null(principal);
        }

        [Fact]
        public async Task GenerateAccessToken_ShouldThrowException_IfSecretMissing()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "brokenenv@example.com"
            };

            var um = MockHelper.MockUserManager().Object;
            var jwtOptions = new JwtSettings()
            {
                Secret = null
            };

            var jwtService = new JwtTokenService(um, jwtOptions);

            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await jwtService.GenerateAccessToken(user);
            });
        }

        [Fact]
        public void GetPrincipalFromExpiredToken_ShouldReturnNull_ForEmptyToken()
        {
            var jwtService = MockHelper.MockJwtTokenService().Object;
            var principal = jwtService.GetPrincipalFromExpiredToken("");
            Assert.Null(principal);
        }

        [Fact]
        public void GetPrincipalFromExpiredToken_ShouldReturnNull_ForNullToken()
        {
            var jwtService = MockHelper.MockJwtTokenService().Object;
            var principal = jwtService.GetPrincipalFromExpiredToken(null!);
            Assert.Null(principal);
        }

        [Fact]
        public async Task GenerateAccessToken_ShouldHaveCorrectExpiration()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                Email = "lifetime@example.com"
            };

            var jwtOptions = new JwtSettings()
            {
                Issuer = "test-issuer",
                Audience = "test-audience",
                Secret = "supersecretkeysupersecretkey123!",
                TokenLifetimeMin = 120
            };

            var userManagerMock = MockHelper.MockUserManager();
            userManagerMock
                .Setup(um => um.GetRolesAsync(It.IsAny<PidrobitokUser>()))
                .ReturnsAsync(new List<string>());

            var jwtService = new JwtTokenService(userManagerMock.Object, jwtOptions);

            var token = await jwtService.GenerateAccessToken(user);

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            var expires = jwtToken.ValidTo;
            var now = DateTime.UtcNow;

            Assert.InRange(expires, now.AddMinutes(119), now.AddMinutes(121));
        }

    }
}
