using System.ComponentModel.DataAnnotations;

namespace AuthService.Models.DTO
{
    public class RegisterModelDto
    {
        [Required]
        public string FirstName { get; set; } = null!;

        [Required]
        public string LastName { get; set; } = null!;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = null!;

        [Required]
        [MinLength(6)]
        public string Password { get; set; } = null!;

        public bool isStudent { get; set; } = true;
    }

}
