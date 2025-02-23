using System.IdentityModel.Tokens.Jwt;
using AuthProject.Data;
using AuthProject.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System;

namespace AuthProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //baseurl/api/userauth
    public class UserAuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManger;
        private readonly SignInManager<ApplicationUser> _signinManger;
        private readonly string? _jwtKey;
        private readonly string? _jwtIssuer;
        private readonly string? _jwtAudience;
        private readonly int _jwtExpiry;

        public UserAuthController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
        {
            _userManger = userManager;
            _signinManger = signInManager;
            _jwtKey = configuration["Jwt:Key"];
            _jwtIssuer = configuration["Jwt:Issuer"];
            _jwtAudience = configuration["Jwt:Audience"];
            _jwtExpiry = int.Parse(configuration["Jwt:ExpiryMinutes"]);

        }
        //baseurl/api/userauth/register
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            if (registerModel == null
                || string.IsNullOrEmpty(registerModel.Name)
                || string.IsNullOrEmpty(registerModel.Email)
                || string.IsNullOrEmpty(registerModel.Password))
            {
                return BadRequest("Invalid Registration details");
            }

            var existingUser = await _userManger.FindByEmailAsync(registerModel.Email);
            if (existingUser != null)
            {
                return Conflict("Email already exist");
            }

            var user = new ApplicationUser
            {
                UserName = registerModel.Email,
                Name = registerModel.Name,
                Email = registerModel.Email,

            };
            var result = await _userManger.CreateAsync(user, registerModel.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            return Ok("User Got Created Successfully");
        }


        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManger.FindByEmailAsync(loginModel.Email);
            if (user == null)
            {
                return Unauthorized(new { success = false, message = "invalid usermane and password" });
            }

            var result = await _signinManger.CheckPasswordSignInAsync(user, loginModel.Password, false);


            if (!result.Succeeded)
            {

                return Unauthorized(new { success = false, message = "invalid usermane and password" });
            }

            var token = GenerateJWTToken(user);
            return Ok(new { success = true, token });
        }

        private string GenerateJWTToken(ApplicationUser user)
        {
            var Claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub,user.Id),
            new Claim(JwtRegisteredClaimNames.Email,user.Email),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()), //jwt id is jti which is used to identitify id uqi
            new Claim("Name",user.Name),
            };

            var Key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey));
            var creds = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                  claims: Claims,
                  expires: DateTime.Now.AddMinutes(_jwtExpiry),
                  signingCredentials: creds);


            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            await _signinManger.SignOutAsync();
            return Ok("User logged out successfully");
        }
    }
}

