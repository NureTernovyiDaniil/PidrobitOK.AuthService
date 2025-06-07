namespace AuthService.Models.DTO
{
    public class RefreshTokenResultDto
    {
        public string AccessToken { get; set; } = default!;
        public string RefreshToken { get; set; } = default!;
    }
}