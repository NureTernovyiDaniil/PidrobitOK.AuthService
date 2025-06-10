using Moq;
using System.Text.Json;
using FluentAssertions;
using AuthService.Models.DTO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using PidrobitOK.AuthService.Models;
using PidrobitOK.AuthService_Test.Helpers;
using PidrobitOK.AuthService.Services;
using System.Security.Claims;
using PidrobitOK.AuthService.Models.DTO;
using AuthService.Controllers;
using Microsoft.Extensions.Logging;

namespace AuthServiceTest.Controllers
{
    public class IdentityControllerTests
    {
        #region Register
        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenModelStateInvalid()
        {
            
            var controller = MockHelper.CreateController();
            controller.ModelState.AddModelError("Email", "Required");
            var result = await controller.Register(new RegisterModelDto());
            result.Should().BeOfType<BadRequestObjectResult>();
        }

        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenUserCreationFails()
        {
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.CreateAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "err" }));
            var rm = MockHelper.MockRoleManager();
            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);
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
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.CreateAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);
            um.Setup(x => x.AddToRoleAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);
            var rm = MockHelper.MockRoleManager();
            rm.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);
            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);
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
        public async Task Register_ShouldReturnBadRequest_WhenAddToRoleFails()
        {
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.CreateAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);
            um.Setup(x => x.AddToRoleAsync(It.IsAny<PidrobitokUser>(), It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "error" }));
            var rm = MockHelper.MockRoleManager();
            rm.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);
            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);

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
        #endregion

        #region Login
        [Fact]
        public async Task Login_ShouldReturnUnauthorized_WhenUserNotFound()
        {
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
              .ReturnsAsync((PidrobitokUser)null);
            var rm = MockHelper.MockRoleManager();
            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);
            var result = await controller.Login(new LoginDto { Email = "x@x", Password = "p" });
            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Login_ShouldReturnUnauthorized_WhenPasswordInvalid()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(false);
            var rm = MockHelper.MockRoleManager();
            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);
            var result = await controller.Login(new LoginDto { Email = "x@x", Password = "p" });
            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Login_ShouldReturnOk_WhenCredentialsValid()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(true);
            um.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);
            var rm = MockHelper.MockRoleManager();
            var jwt = MockHelper.MockJwtTokenService();
            jwt.Setup(x => x.GenerateAccessToken(It.IsAny<PidrobitokUser>())).ReturnsAsync("mocked-access-token");
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);

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
        public async Task Login_ShouldReturnBadRequest_IfUpdateFails()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(true);
            um.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Failed());
            var rm = MockHelper.MockRoleManager();
            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var result = await controller.Login(new LoginDto { Email = "x@x", Password = "p" });

            result.Should().BeOfType<BadRequestObjectResult>();
        }
        #endregion

        #region Refresh
        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenTokenInvalid()
        {
            var um = MockHelper.MockUserManager();
            var rm = MockHelper.MockRoleManager();
            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);
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
            var um = MockHelper.MockUserManager();

            um.Setup(x => x.FindByIdAsync(userId.ToString())).ReturnsAsync((PidrobitokUser)null);

            var rm = MockHelper.MockRoleManager();

            var jwt = new Mock<IJwtTokenService>();

            jwt.Setup(x => x.GetPrincipalFromExpiredToken(It.IsAny<string>()))
               .Returns(new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
               {
           new Claim(ClaimTypes.NameIdentifier, userId.ToString())
               }, "mock")));

            var logger = MockHelper.MockLogger();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var dto = new RefreshTokenResultDto
            {
                AccessToken = "some-access-token",
                RefreshToken = "some-refresh-token"
            };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Refresh_ShouldReturnUnauthorized_WhenRefreshTokenExpired()
        {
            var um = MockHelper.MockUserManager();
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                RefreshToken = "valid",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddSeconds(-10)
            };

            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);

            var rm = MockHelper.MockRoleManager();

            var jwt = MockHelper.MockJwtTokenService();

            jwt.Setup(x => x.GetPrincipalFromExpiredToken(It.IsAny<string>()))
               .Returns(new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
               {
           new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
               }, "mock")));

            jwt.Setup(x => x.GenerateAccessToken(It.IsAny<PidrobitokUser>()))
               .ReturnsAsync("mocked-access-token");

            jwt.Setup(x => x.GenerateRefreshToken())
               .Returns("mocked-refresh-token");

            var logger = MockHelper.MockLogger();

            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var dto = new RefreshTokenResultDto { AccessToken = "some-token", RefreshToken = "valid" };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<UnauthorizedObjectResult>();
        }

        [Fact]
        public async Task Refresh_ShouldReturnUnauthorized_WhenRefreshTokenInvalid()
        {
            var um = MockHelper.MockUserManager();
            var user = new PidrobitokUser
            {
                Id = Guid.NewGuid(),
                RefreshToken = "expected",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(10)
            };

            um.Setup(x => x.FindByIdAsync(user.Id.ToString())).ReturnsAsync(user);

            var rm = MockHelper.MockRoleManager();

            var jwt = new Mock<IJwtTokenService>();

            jwt.Setup(x => x.GetPrincipalFromExpiredToken(It.IsAny<string>()))
               .Returns(new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
               {
           new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
               }, "mock")));

            jwt.Setup(x => x.GenerateAccessToken(It.IsAny<PidrobitokUser>()))
               .ReturnsAsync("new-access-token");

            jwt.Setup(x => x.GenerateRefreshToken())
               .Returns("new-refresh-token");

            var logger = MockHelper.MockLogger();

            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var dto = new RefreshTokenResultDto { AccessToken = "some-token", RefreshToken = "other" }; // "other" != "expected"

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<UnauthorizedObjectResult>();
        }


        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenAccessTokenIsMissing()
        {
            var controller = MockHelper.CreateController();
            var dto = new RefreshTokenResultDto { AccessToken = null, RefreshToken = "refresh" };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
        }


        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenRefreshTokenIsMissing()
        {
            var controller = MockHelper.CreateController();
            var dto = new RefreshTokenResultDto { AccessToken = "access", RefreshToken = null };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
        }


        [Fact]
        public async Task Refresh_ShouldReturnBadRequest_WhenAccessTokenInvalid()
        {
            var controller = MockHelper.CreateController();

            var dto = new RefreshTokenResultDto
            {
                AccessToken = "invalid-token-here",
                RefreshToken = "some-refresh"
            };

            var result = await controller.Refresh(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
        }
        #endregion
        
        #region ChangeRole

        [Fact]
        public async Task ChangeRole_ShouldReturnBadRequest_WhenModelStateInvalid()
        {
            var controller = MockHelper.CreateController();
            controller.ModelState.AddModelError("UserId", "Required");

            var result = await controller.ChangeRole(new ChangeRoleDto());

            result.Should().BeOfType<BadRequestObjectResult>();
        }

        [Fact]
        public async Task ChangeRole_ShouldReturnBadRequest_WhenUserNotFound()
        {
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync((PidrobitokUser)null);
            
            var controller = MockHelper.CreateController(um);

            var result = await controller.ChangeRole(new ChangeRoleDto
            {
                UserId = Guid.NewGuid(),
                RoleName = "Admin"
            });

            result.Should().BeOfType<BadRequestObjectResult>().Which.Value.Should().Be("Invalid user id");
        }

        [Fact]
        public async Task ChangeRole_ShouldReturnBadRequest_WhenRoleNotFound()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(user);

            var rm = MockHelper.MockRoleManager();
            rm.Setup(x => x.FindByNameAsync(It.IsAny<string>())).ReturnsAsync((PidrobitokRole)null);

            var jwt = MockHelper.MockJwtTokenService();
            var logger = MockHelper.MockLogger();

            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var dto = new ChangeRoleDto
            {
                UserId = Guid.NewGuid(),
                RoleName = "NonExistentRole"
            };

            var result = await controller.ChangeRole(dto);

            result.Should().BeOfType<BadRequestObjectResult>();
            var badRequest = result as BadRequestObjectResult;
            badRequest.Value.Should().Be("Invalid role name");
        }


        [Fact]
        public async Task ChangeRole_ShouldReturnBadRequest_WhenRemovingRolesFails()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });
            um.Setup(x => x.RemoveFromRolesAsync(user, It.IsAny<IEnumerable<string>>()))
              .ReturnsAsync(IdentityResult.Failed());

            var rm = MockHelper.MockRoleManager();
            rm.Setup(x => x.FindByNameAsync(It.IsAny<string>())).ReturnsAsync(new PidrobitokRole());

            var jwt = new Mock<IJwtTokenService>();
            var logger = new Mock<ILogger<IdentityController>>();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var result = await controller.ChangeRole(new ChangeRoleDto
            {
                UserId = Guid.NewGuid(),
                RoleName = "Admin"
            });

            result.Should().BeOfType<BadRequestObjectResult>().Which.Value.Should().Be("Failed to remove existing roles");
        }

        [Fact]
        public async Task ChangeRole_ShouldReturnBadRequest_WhenAddingRoleFails()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });
            um.Setup(x => x.RemoveFromRolesAsync(user, It.IsAny<IEnumerable<string>>()))
              .ReturnsAsync(IdentityResult.Success);
            um.Setup(x => x.AddToRoleAsync(user, It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Failed());

            var rm = MockHelper.MockRoleManager();
            rm.Setup(x => x.FindByNameAsync(It.IsAny<string>())).ReturnsAsync(new PidrobitokRole());

            var jwt = new Mock<IJwtTokenService>();
            var logger = new Mock<ILogger<IdentityController>>();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var result = await controller.ChangeRole(new ChangeRoleDto
            {
                UserId = Guid.NewGuid(),
                RoleName = "Admin"
            });

            result.Should().BeOfType<BadRequestObjectResult>().Which.Value.Should().Be("Failed to assign new role");
        }

        [Fact]
        public async Task ChangeRole_ShouldReturnOk_WhenSuccessful()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });
            um.Setup(x => x.RemoveFromRolesAsync(user, It.IsAny<IEnumerable<string>>()))
              .ReturnsAsync(IdentityResult.Success);
            um.Setup(x => x.AddToRoleAsync(user, It.IsAny<string>()))
              .ReturnsAsync(IdentityResult.Success);

            var rm = MockHelper.MockRoleManager();
            rm.Setup(x => x.FindByNameAsync(It.IsAny<string>())).ReturnsAsync(new PidrobitokRole());

            var jwt = new Mock<IJwtTokenService>();
            var logger = new Mock<ILogger<IdentityController>>();
            var controller = MockHelper.CreateController(um, rm, jwt, logger);

            var result = await controller.ChangeRole(new ChangeRoleDto
            {
                UserId = Guid.NewGuid(),
                RoleName = "Admin"
            });

            result.Should().BeOfType<OkObjectResult>().Which.Value.Should().Be("User role updated successfully");
        }
        #endregion

        #region BanUser
        [Fact]
        public async Task BanUser_ShouldReturnBadRequest_WhenUserNotFound()
        {
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync((PidrobitokUser)null);
            var controller = MockHelper.CreateController(um);

            var result = await controller.BanUser(Guid.NewGuid());

            result.Should().BeOfType<BadRequestObjectResult>().Which.Value.Should().Be("User not found");
        }

        [Fact]
        public async Task BanUser_ShouldReturnOk_WhenUserSuccessfullyBanned()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

            var controller = MockHelper.CreateController(um);

            var result = await controller.BanUser(Guid.NewGuid());

            result.Should().BeOfType<OkObjectResult>().Which.Value.Should().Be("User successfuly baned");
        }

        [Fact]
        public async Task BanUser_ShouldReturnBadRequest_WhenUpdateFails()
        {
            var user = new PidrobitokUser();
            var um = MockHelper.MockUserManager();
            um.Setup(x => x.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(user);
            um.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Failed());

            var controller = MockHelper.CreateController(um);

            var result = await controller.BanUser(Guid.NewGuid());

            result.Should().BeOfType<BadRequestObjectResult>().Which.Value.Should().Be("An error occurred");
        }
        #endregion
    }
}