using AngularAuthAPI.Context;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.SqlServer.Query.Internal;

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

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username==userObj.Username && x.Password==userObj.Password);
            if(user == null)
                   return NotFound(new {Message = "User not found!"});
            return Ok(new { Message = "Login succesfull!" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody]User userObj)
        {
            if (userObj == null)
                return BadRequest(new { Message = "Enter correct details" });

            await _authContext.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User registered successfully!" });
        }

    }
}
