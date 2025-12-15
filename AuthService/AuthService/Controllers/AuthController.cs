using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]/[action]")]
public class AuthController : ControllerBase
{
    [HttpGet]
    public async Task<string> GetAccessToken()
    {
        
    }
}