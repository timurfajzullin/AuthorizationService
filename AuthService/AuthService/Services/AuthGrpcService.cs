using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Models;
using AuthService.Protos;
using Grpc.Core;
using Grpc.AspNetCore.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using LoginRequest = AuthService.Protos.LoginRequest;
using RegisterRequest = AuthService.Protos.RegisterRequest;

namespace AuthService.Services;

public class AuthGrpcService : Auth.AuthBase
{
    private readonly AuthDbContext _db;
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly JwtOptions _jwtOptions;

    public AuthGrpcService(AuthDbContext db, IPasswordHasher<User> passwordHasher, IOptions<JwtOptions> jwtOptions)
    {
        _db = db;
        _passwordHasher = passwordHasher;
        _jwtOptions = jwtOptions.Value ?? throw new InvalidOperationException("Jwt options are not configured");
    }

    public override async Task<RegisterReply> Register(RegisterRequest request, ServerCallContext context)
    {
        if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
        {
            return new RegisterReply { Success = false, Message = "login and password are required" };
        }

        var normalized = request.Login.ToUpperInvariant();
        var exists = await _db.Users.AnyAsync(u => u.LoginNormalized == normalized, context.CancellationToken);
        if (exists)
        {
            return new RegisterReply { Success = false, Message = "user already exists" };
        }

        var user = new User
        {
            Login = request.Login,
            LoginNormalized = normalized
        };
        user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);

        _db.Users.Add(user);
        await _db.SaveChangesAsync(context.CancellationToken);

        return new RegisterReply { Success = true, Message = "user created" };
    }

    public override async Task<LoginReply> Login(LoginRequest request, ServerCallContext context)
    {
        if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
        {
            return new LoginReply { Success = false, Message = "login and password are required" };
        }

        var normalized = request.Login.ToUpperInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.LoginNormalized == normalized, context.CancellationToken);
        var success = false;

        if (user is not null)
        {
            var verification = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            success = verification != PasswordVerificationResult.Failed;
        }

        var httpContext = context.GetHttpContext();
        var loginLog = new LoginEntry
        {
            Login = request.Login,
            LoginNormalized = normalized,
            Success = success,
            UserAgent = httpContext.Request.Headers.UserAgent.ToString(),
            RemoteIp = httpContext.Connection.RemoteIpAddress?.ToString(),
            OccurredAtUtc = DateTime.UtcNow
        };
        _db.Logins.Add(loginLog);

        if (!success)
        {
            await _db.SaveChangesAsync(context.CancellationToken);
            return new LoginReply { Success = false, Message = "invalid credentials" };
        }

        var token = GenerateToken(user!.Login);
        var reply = new LoginReply
        {
            Success = true,
            Message = "ok",
            AccessToken = token,
            TokenType = "Bearer",
            ExpiresInMinutes = _jwtOptions.AccessTokenMinutes
        };

        await _db.SaveChangesAsync(context.CancellationToken);
        return reply;
    }

    private string GenerateToken(string login)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, login),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtOptions.AccessTokenMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

