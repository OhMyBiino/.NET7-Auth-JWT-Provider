using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc;
using dotnet7JwtToken.Models;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace dotnet7JwtToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        //Database
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //register
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request) 
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            //before saving, check if username already used
            user.Username = request.UserName;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }

        //login
        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserDto request) 
        {
            //fetch record that matches with request username data

            if (user.Username != request.UserName) 
            {
                return BadRequest("User not found");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash)) 
            {
                return BadRequest("Wrong password.");
            }

            //generate token
            string token = GenereateJsonWebToken();
            return Ok(token);
        }

        [HttpGet("/Username"), Authorize]
        public async Task<ActionResult<string>> GetUserName() 
        {
            return Ok(user.Username);
        }



        //generate token
        private string GenereateJsonWebToken() 
        {
            //claims
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            //key
            var key = new SymmetricSecurityKey(Encoding.UTF8
                    .GetBytes(_configuration.GetSection("SecurityKey:Token").Value!)); //from Microsoft.IdentityModel.Tokens

            //credentials
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //token
            var token = new JwtSecurityToken(           //class from System.IdentityModel.Tokens;
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials : credentials
                ); 

            //write token
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);   //class from System.IdentityModel.Tokens.Jwt;

            return jwt;
        }
    }
}
