using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.SqlServer.Query.Internal;
using AngularAuthAPI.Helpers;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext dbContext)
        {
            _authContext = dbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody]User userObj)
        {
            if (userObj == null)
                return BadRequest(new { Message = "Enter correct details" });

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username==userObj.Username);

            if(user == null)
                   return NotFound(new {Message = "User not found!"});

            var storedHashPassword = await _authContext.Users
                .Where(x => x.Username == userObj.Username)
                .Select(x => x.Password)
                .FirstOrDefaultAsync();

            if(PasswordHasher.VerifyPassword(userObj.Password, storedHashPassword) == false)
                return Unauthorized(new { Message = "Invalid password!" });
            return Ok(new { Message = "Login succesfull!" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody]User userObj)
        {
            if (userObj == null)
                return BadRequest(new { Message = "Enter correct details" });

            if(await CheckUserNameExists(userObj.Username))
            {
                return BadRequest(new { Message = "Username already exists!" });
            }
            if(await CheckEmailExists(userObj.Email))
            {
                return BadRequest(new { Message = "Email already exists!" });
            }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User"; // Default role, can be changed later
            userObj.Token = "";
            await _authContext.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User registered successfully!" });
        }

        private async Task<bool> CheckUserNameExists(string username) =>
            await _authContext.Users.AnyAsync(x => x.Username == username);


        private async Task<bool> CheckEmailExists(string email) => 
            await _authContext.Users.AnyAsync(x => x.Email == email);


    }
}
