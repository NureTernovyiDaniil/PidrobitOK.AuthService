using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PidrobitOK.AuthService.Migrations
{
    /// <inheritdoc />
    public partial class UpdateUserModelForIsBanedField : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsBaned",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsBaned",
                table: "AspNetUsers");
        }
    }
}
