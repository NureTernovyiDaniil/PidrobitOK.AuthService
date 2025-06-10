using AuthService.Controllers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Moq;
using PidrobitOK.AuthService.Models;
using PidrobitOK.AuthService.Services;

namespace PidrobitOK.AuthService_Test.Helpers
{
    public static class MockHelper
    {
        public static Mock<ILogger<IdentityController>> MockLogger()
        {
            return new Mock<ILogger<IdentityController>>();
        }

        public static Mock<IJwtTokenService> MockJwtTokenService()
        {
            var jwt = new Mock<IJwtTokenService>();

            jwt.Setup(x => x.GenerateAccessToken(It.IsAny<PidrobitokUser>()))
                .ReturnsAsync("mocked-access-token");

            jwt.Setup(x => x.GenerateRefreshToken())
                .Returns("mocked-refresh-token");

            return jwt;
        }

        public static Mock<UserManager<PidrobitokUser>> MockUserManager()
        {
            var store = new Mock<IUserStore<PidrobitokUser>>();
            return new Mock<UserManager<PidrobitokUser>>(store.Object, null, null, null, null, null, null, null, null);
        }

        public static Mock<RoleManager<IdentityRole<Guid>>> MockRoleManager()
        {
            var store = new Mock<IRoleStore<IdentityRole<Guid>>>();
            return new Mock<RoleManager<IdentityRole<Guid>>>(store.Object, null, null, null, null);
        }

        public static IdentityController CreateController(
            Mock<UserManager<PidrobitokUser>> um = null,
            Mock<RoleManager<IdentityRole<Guid>>> rm = null,
            Mock<IJwtTokenService> jwt = null,
            Mock<ILogger<IdentityController>> logger = null)
        {
            if(um == null)
            {
                um = MockUserManager();
            }
            if(rm == null)
            {
                rm = MockRoleManager();
            }
            if(jwt == null)
            {
                jwt = MockJwtTokenService();
            }
            if(logger == null)
            {
                logger = MockLogger();
            }

            return new IdentityController(um.Object, rm.Object, jwt.Object, logger.Object);
        }

        public static IdentityController CreateController()
        {
            var um = MockUserManager();
            var rm = MockRoleManager();
            var jwt = MockJwtTokenService();
            var logger = MockLogger();

            return new IdentityController(um.Object, rm.Object, jwt.Object, logger.Object);
        }
    }
}
