using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _appDbContext;
        public UserController(AppDbContext appDbContext)
        {
                _appDbContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null) { return BadRequest(); }

            var user = await _appDbContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);
            if (user == null) { return NotFound(new { Message = "User not found" }); }

            if (!PasswordHasher.VerifyPassword(userObj.Password,user.Password))
            {
                return BadRequest(new { Message = "Password is incorrect" });
            }


            user.Token = CreateJwt(user);


            return Ok(new
            {
                Token = user.Token,
                Message="Logged In"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User userObj)
        {
            if (userObj == null) { return BadRequest(); }

            //check username
            if (await checkUserNameExists(userObj.UserName))
            {
                return BadRequest(new { Message = "User Already exists" });
            }

            //check email
            if (await checkEmailExists(userObj.Email))
            {
                return BadRequest(new { Message = "Email Already exists" });
            }

            //check password strength
            var password = CheckPassword(userObj.Password);
            if (!string.IsNullOrEmpty(password))
            {
                return BadRequest(new {Message= password});
            }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _appDbContext.Users.AddAsync(userObj);
            await _appDbContext.SaveChangesAsync();
            return Ok(new { Message="User registered:"});

        }

        private string CheckPassword(string password)
        {
            StringBuilder stringBuilder = new StringBuilder();
            if (password.Length<8)
                stringBuilder.Append("Minimum Password length should be 8 characters.");

            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]"))
            {
                stringBuilder.Append("Password Should contain atleast in special character.");
            }

            // Check if the password is alphanumeric (contains letters and digits)
            if (!Regex.IsMatch(password, @"[0-9]"))
            {
                stringBuilder.Append("Password should contain atleast one number.");
            }


            return stringBuilder.ToString();

        }

        private Task<bool> checkUserNameExists(string userName)  
        {
            return _appDbContext.Users.AnyAsync(x => x.UserName == userName);
        }
        private Task<bool> checkEmailExists(string email)
        {
            return _appDbContext.Users.AnyAsync(x => x.Email == email);
        }


        private string CreateJwt(User user)
        {
            var jwtTokenHandler= new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("BananaBananaBanana");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name,$"{user.FirstName}:{user.LastName}")
            });

            var credentials= new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };

            var token= jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);


        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            var data= await _appDbContext.Users.ToListAsync();
            return Ok(data);
        }
    }
}
