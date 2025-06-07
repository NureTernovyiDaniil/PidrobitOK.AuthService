using Microsoft.AspNetCore.Identity;
using PidrobitOK.AuthService.Models;

namespace PidrobitOK.AuthService.Services
{
    public class StartupTasksService
    {
        private readonly UserManager<PidrobitokUser> _userManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;

        public StartupTasksService(UserManager<PidrobitokUser> userManager,
            RoleManager<IdentityRole<Guid>> roleManager,
            ILogger<StartupTasksService> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task EnsureRolesExist()
        {
            var roles = new[] { "Student", "Employer", "Admin" };

            foreach (var role in roles)
            {
                var roleExists = await _roleManager.RoleExistsAsync(role);
                if (!roleExists)
                {
                    var newRole = new IdentityRole<Guid> { Name = role };
                    await _roleManager.CreateAsync(newRole);
                }
            }
        }

        public  async Task EnsureAdminExist()
        {
            var existedAdmin = await _userManager.FindByEmailAsync("admin@nure.ua");
            if(existedAdmin == null)
            {
                var user = new PidrobitokUser
                {
                    UserName = "admin",
                    Email = "admin@nure.ua",
                };

                var result = await _userManager.CreateAsync(user, Environment.GetEnvironmentVariable("JWT_SECRET"));
                if (!result.Succeeded)
                {
                    throw new Exception("Error while creating admin account");
                }

                var roleResult = await _userManager.AddToRoleAsync(user, "Admin");
                if (!roleResult.Succeeded)
                {
                    throw new Exception("Error while seting admin role");
                }
            }
        }
    }
}
