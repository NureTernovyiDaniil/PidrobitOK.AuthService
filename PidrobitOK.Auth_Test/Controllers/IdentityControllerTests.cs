using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthService.Controllers;
using AuthService.Models;
using AuthService.Models.DTO;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using Xunit;
using System.Text.Json;
using PidrobitOK.AuthService.Models;

namespace AuthServiceTest.Controllers
{
    public class IdentityControllerTests
    {
        public IdentityControllerTests()
        {
            Environment.SetEnvironmentVariable("JWT_ISSUER", "test");
            Environment.SetEnvironmentVariable("JWT_AUDIENCE", "test");
            Environment.SetEnvironmentVariable("JWT_SECRET", "supersecretkeysupersecretkey123!");
            Environment.SetEnvironmentVariable("JWT_TOKEN_LIFETIME", "60");
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Testing");
        }

        private static Mock<UserManager<PidrobitokUser>> MockUserManager()
        {
            var store = new Mock<IUserStore<PidrobitokUser>>();
            return new Mock<UserManager<PidrobitokUser>>(store.Object, null, null, null, null, null, null, null, null);
        }

        private static Mock<RoleManager<IdentityRole<Guid>>> MockRoleManager()
        {
            var store = new Mock<IRoleStore<IdentityRole<Guid>>>();
            return new Mock<RoleManager<IdentityRole<Guid>>>(store.Object, null, null, null, null);
        }

        private static IdentityController CreateController(
            Mock<UserManager<PidrobitokUser>> um,
            Mock<RoleManager<IdentityRole<Guid>>> rm,
            JwtTokenService jwt)
        {
            var config = new ConfigurationBuilder().Build();
            return new IdentityController(um.Object, rm.Object, jwt, config);
        }

        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenModelStateInvalid()
        {
            var um = MockUserManager();
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);
            controller.ModelState.AddModelError("Email", "Required");
            var result = await controller.Register(new RegisterModelDto());
            result.Should().BeOfType<BadRequestObjectResult>();
        }

        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenUserCreationFails()
        {
            var um = MockUserManager();
            um.Setup(x => x.CreateAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "err" }));
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);
            var dto = new RegisterModelDto
            {
                Email = "e@e.com",
                Password = "123456",
                FirstName = "f",
                LastName = "l"
            };
            var result = await controller.Register(dto);
            result.Should().BeOfType<BadRequestObjectResult>();
        }

        [Fact]
        public async Task Register_ShouldReturnOk_WhenSuccessful()
        {
            var um = MockUserManager();
            um.Setup(x => x.CreateAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);
            um.Setup(x => x.AddToRoleAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);
            var rm = MockRoleManager();
            rm.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);
            var dto = new RegisterModelDto
            {
                Email = "e@e.com",
                Password = "123456",
                FirstName = "f",
                LastName = "l"
            };
            var result = await controller.Register(dto);
            result.Should().BeOfType<OkObjectResult>();
        }

        [Fact]
        public async Task Login_ShouldReturnUnauthorized_WhenUserNotFound()
        {
            var um = MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
              .ReturnsAsync((PidrobitokUser)null);
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);
            var result = await controller.Login(new LoginDto { Email = "x@x", Password = "p" });
            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Login_ShouldReturnUnauthorized_WhenPasswordInvalid()
        {
            var user = new PidrobitokUser();
            var um = MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(false);
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);
            var result = await controller.Login(new LoginDto { Email = "x@x", Password = "p" });
            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Login_ShouldReturnOk_WhenCredentialsValid()
        {
            var user = new PidrobitokUser();
            var um = MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(true);
            um.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);

            var result = await controller.Login(new LoginDto { Email = "x@x", Password = "p" });

            result.Should().BeOfType<OkObjectResult>();

            var okResult = result as OkObjectResult;
            var json = JsonSerializer.Serialize(okResult.Value);
            var jsonObj = JsonSerializer.Deserialize<JsonElement>(json);

            jsonObj.TryGetProperty("Token", out var token).Should().BeTrue();
            jsonObj.TryGetProperty("RefreshToken", out var refresh).Should().BeTrue();

            token.GetString().Should().NotBeNullOrWhiteSpace();
            refresh.GetString().Should().NotBeNullOrWhiteSpace();
        }


        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenTokenInvalid()
        {
            var um = MockUserManager();
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);
            var result = await controller.Refresh(new RefreshTokenResultDto
            {
                AccessToken = "invalid.token",
                RefreshToken = "some-refresh"
            });
            result.Should().BeOfType<BadRequestObjectResult>();
        }

        [Fact]
        public async Task Refresh_ShouldReturnUnauthorized_WhenUserNotFound()
        {
            var userId = Guid.NewGuid();
            var accessToken = new JwtTokenService().GenerateAccessToken(new PidrobitokUser
            {
                Id = userId,
                Email = "test@example.com"
            });

            var principal = new JwtTokenService().GetPrincipalFromExpiredToken(accessToken);

            var um = MockUserManager();
            um.Setup(x => x.FindByIdAsync(userId.ToString())).ReturnsAsync((PidrobitokUser)null);
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);

            var result = await controller.Refresh(new RefreshTokenResultDto
            {
                AccessToken = accessToken,
                RefreshToken = "invalid"
            });

            result.Should().BeOfType<UnauthorizedObjectResult>();
        }



        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenAddToRoleFails()
        {
            var um = MockUserManager();
            um.Setup(x => x.CreateAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);
            um.Setup(x => x.AddToRoleAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "error" }));
            var rm = MockRoleManager();
            rm.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);

            var dto = new RegisterModelDto
            {
                Email = "e@e.com",
                Password = "123456",
                FirstName = "f",
                LastName = "l"
            };

            var result = await controller.Register(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
        }

        [Fact]
        public async Task Login_ShouldReturnOk_EvenIfUpdateFails()
        {
            var user = new PidrobitokUser();
            var um = MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(true);
            um.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Failed());
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);

            var result = await controller.Login(new LoginDto { Email = "x@x", Password = "p" });

            result.Should().BeOfType<OkObjectResult>();
        }


        [Fact]
        public async Task Refresh_ShouldReturnUnauthorized_WhenRefreshTokenExpired()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                RefreshToken = "valid",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddSeconds(-10) // уже истёк
            };

            var accessToken = new JwtTokenService().GenerateAccessToken(user);
            var um = MockUserManager();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);

            var dto = new RefreshTokenResultDto { AccessToken = accessToken, RefreshToken = "valid" };
            var result = await controller.Refresh(dto);

            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Refresh_ShouldReturnUnauthorized_WhenRefreshTokenInvalid()
        {
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                RefreshToken = "expected",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(10)
            };

            var accessToken = new JwtTokenService().GenerateAccessToken(user);
            var um = MockUserManager();
            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);
            var rm = MockRoleManager();
            var jwt = new JwtTokenService();
            var controller = CreateController(um, rm, jwt);

            var dto = new RefreshTokenResultDto { AccessToken = accessToken, RefreshToken = "other" };
            var result = await controller.Refresh(dto);

            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenAccessTokenIsMissing()
        {
            var controller = CreateController(MockUserManager(), MockRoleManager(), new JwtTokenService());
            var dto = new RefreshTokenResultDto { AccessToken = null, RefreshToken = "refresh" };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
        }


        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenRefreshTokenIsMissing()
        {
            var controller = CreateController(MockUserManager(), MockRoleManager(), new JwtTokenService());
            var dto = new RefreshTokenResultDto { AccessToken = "access", RefreshToken = null };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
        }


        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenAccessTokenInvalid()
        {
            var jwt = new JwtTokenService();
            var controller = CreateController(MockUserManager(), MockRoleManager(), jwt);

            var dto = new RefreshTokenResultDto
            {
                AccessToken = "invalid-token-here",
                RefreshToken = "some-refresh"
            };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
        }


    }
}