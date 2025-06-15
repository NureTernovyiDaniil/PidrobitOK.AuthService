using AuthService.Models.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PidrobitOK.AuthService.Models;
using PidrobitOK.AuthService.Models.DTO;
using PidrobitOK.AuthService.Services;
using System.Security.Claims;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        private readonly UserManager<PidrobitokUser> _userManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly ILogger<IdentityController> _logger;

        public IdentityController(
            UserManager<PidrobitokUser> userManager,
            RoleManager<IdentityRole<Guid>> roleManager,
            IJwtTokenService jwtTokenService,
            ILogger<IdentityController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtTokenService = jwtTokenService;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModelDto model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var user = new PidrobitokUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors);
                }

                var role = model.isStudent ? "Student" : "Employer";
                var roleResult = await _userManager.AddToRoleAsync(user, role);
                if (!roleResult.Succeeded)
                {
                    return BadRequest(roleResult.Errors);
                }

                return Ok("User registered successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
            }

            return BadRequest("An error occurred");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto login)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var user = await _userManager.FindByEmailAsync(login.Email);
                if (user == null || !await _userManager.CheckPasswordAsync(user, login.Password))
                {
                    return Unauthorized("Invalid credentials");
                }

                if(user.IsBaned)
                {
                    return Unauthorized("You have been banned for violating the platform rules");
                }

                var accessToken = await _jwtTokenService.GenerateAccessToken(user);
                var refreshToken = _jwtTokenService.GenerateRefreshToken();

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    return BadRequest("Failed to update user");
                }

                return Ok(new
                {
                    Token = accessToken,
                    RefreshToken = refreshToken
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
            }

            return BadRequest("An error occurred");
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenResultDto request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var principal = _jwtTokenService.GetPrincipalFromExpiredToken(request.AccessToken);
                if (principal == null)
                {
                    return BadRequest("Invalid access token.");
                }

                var userIdClaim = principal.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                {
                    return BadRequest("Invalid user ID in token.");
                }

                var user = await _userManager.FindByIdAsync(userId.ToString());
                if (user == null || user.RefreshToken != request.RefreshToken || user.RefreshTokenExpiryTime < DateTime.UtcNow)
                {
                    return Unauthorized("Invalid refresh token.");
                }

                var newAccessToken = _jwtTokenService.GenerateAccessToken(user);
                var newRefreshToken = _jwtTokenService.GenerateRefreshToken();

                user.RefreshToken = newRefreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
                await _userManager.UpdateAsync(user);

                return Ok(new
                {
                    Token = newAccessToken,
                    RefreshToken = newRefreshToken
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
            }

            return BadRequest("An error occurred");
        }

        [Authorize]
        [HttpGet("getUserInfo/{userId}")]
        public async Task<IActionResult> GetUserInfo(Guid userId)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if(user != null)
            {
                return Ok(new UserInfoDto() { Email = user.Email, FirstName = user.FirstName, LastName = user.LastName });
            }

            return NotFound();
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("changeRole")]
        public async Task<IActionResult> ChangeRole([FromBody] ChangeRoleDto changeRoleDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var user = await _userManager.FindByIdAsync(changeRoleDto.UserId.ToString());
                if (user == null)
                {
                    return BadRequest("Invalid user id");
                }

                var role = await _roleManager.FindByNameAsync(changeRoleDto.RoleName);
                if (role == null)
                {
                    return BadRequest("Invalid role name");
                }

                var currentRoles = await _userManager.GetRolesAsync(user);
                var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                if (!removeResult.Succeeded)
                {
                    return BadRequest("Failed to remove existing roles");
                }

                var addResult = await _userManager.AddToRoleAsync(user, changeRoleDto.RoleName);
                if (!addResult.Succeeded)
                {
                    return BadRequest("Failed to assign new role");
                }

                return Ok("User role updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                return BadRequest("An error occurred");
            }
        }

        [Authorize(Roles = "Admin, Moderator")]
        [HttpPost("banUser")]
        public async Task<IActionResult> BanUser(Guid userId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId.ToString());
                if (user == null)
                {
                    return BadRequest("User not found");
                }

                user.IsBaned = true;

                var updateResult = await _userManager.UpdateAsync(user);

                if (!updateResult.Succeeded) 
                {
                    throw new Exception("Error while user updating");
                }

                return Ok("User successfuly baned");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                return BadRequest("An error occurred");
            }
        }
    }
}
