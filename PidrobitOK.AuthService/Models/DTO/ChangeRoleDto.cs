namespace PidrobitOK.AuthService.Models.DTO
{
    public class ChangeRoleDto
    {
        public Guid UserId { get; set; }
        public string RoleName { get; set; }
    }
}
