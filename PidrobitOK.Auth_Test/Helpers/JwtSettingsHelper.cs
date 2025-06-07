using PidrobitOK.AuthService.Options;

namespace PidrobitOK.AuthService_Test.Helpers
{
    public static class JwtSettingsHelper
    {
        public static JwtSettings GetTestJwtSettings()
        {
            return new JwtSettings
            {
                Issuer = "test",
                Audience = "test",
                Secret = "supersecretkeysupersecretkey123!",
                TokenLifetimeMin = 60
            };
        }
    }
}
