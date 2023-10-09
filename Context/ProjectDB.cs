using Microsoft.EntityFrameworkCore;
using DotNetCore6DemoProject.Models.Auth;

namespace DotNetCore6DemoProject.Context

{
    public class ProjectDB : DbContext
    {
        public ProjectDB(DbContextOptions<ProjectDB> options) : base(options)
        {
        }
        public DbSet<UserDTO> Users { get; set; } = null!;
    }
}
