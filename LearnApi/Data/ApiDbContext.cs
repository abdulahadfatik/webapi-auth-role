using LearnApi.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LearnApi.Data
{
    public class ApiDbContext : IdentityDbContext
    {
        public virtual DbSet<Employee> Employees { get; set; }
        public virtual DbSet<RefreshToken> RefreshTokens { get; set; }
        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options)
        {

        }

    }
}
