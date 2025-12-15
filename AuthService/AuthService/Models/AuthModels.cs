using Microsoft.EntityFrameworkCore;

namespace AuthService.Models;

public record RegisterRequest(string Login, string Password);
public record LoginRequest(string Login, string Password);

public class AuthResponse
{
    public string AccessToken { get; set; } = default!;
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresInMinutes { get; set; }
}

public class JwtOptions
{
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string Key { get; set; } = string.Empty;
    public int AccessTokenMinutes { get; set; } = 60;
}

public class User
{
    public int Id { get; set; }
    public string Login { get; set; } = string.Empty;
    public string LoginNormalized { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

public class LoginEntry
{
    public long Id { get; set; }
    public string Login { get; set; } = string.Empty;
    public string LoginNormalized { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? RemoteIp { get; set; }
    public string? UserAgent { get; set; }
    public DateTime OccurredAtUtc { get; set; } = DateTime.UtcNow;
}

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<LoginEntry> Logins => Set<LoginEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.Id);
            entity.Property(u => u.Login).HasMaxLength(200).IsRequired();
            entity.Property(u => u.LoginNormalized).HasMaxLength(200).IsRequired();
            entity.Property(u => u.PasswordHash).IsRequired();
            entity.Property(u => u.CreatedAtUtc).HasDefaultValueSql("now()");
            entity.HasIndex(u => u.LoginNormalized).IsUnique();
        });

        modelBuilder.Entity<LoginEntry>(entity =>
        {
            entity.HasKey(l => l.Id);
            entity.Property(l => l.Login).HasMaxLength(200).IsRequired();
            entity.Property(l => l.LoginNormalized).HasMaxLength(200).IsRequired();
            entity.Property(l => l.RemoteIp).HasMaxLength(100);
            entity.Property(l => l.UserAgent).HasMaxLength(512);
            entity.Property(l => l.OccurredAtUtc).HasDefaultValueSql("now()");
        });
    }
}
