using LearnApi.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace LearnApi.Controllers
{
    [Route("Setup/[action]")]
    [ApiController]
    public class SetupController : ControllerBase
    {
        private readonly ApiDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<SetupController> _logger;

        public SetupController(
            ApiDbContext context,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<SetupController> logger
            )
        {

            _logger = logger;
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpGet]
        public IActionResult GetAllRoles()
        {
            var roles = _roleManager.Roles.ToList();
            return Ok(roles);
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(string name)
        {
            var roleExist = await _roleManager.RoleExistsAsync(name);

            if (!roleExist)
            {
                var roleResult = await _roleManager.CreateAsync(new IdentityRole(name));

                if (roleResult.Succeeded)
                {
                    _logger.LogInformation($"Role {name} has already added successfully");
                    return Ok(new
                    {
                        result=$"role {name} has added successfully"
                    });
                }
                else
                {
                    _logger.LogInformation($"Role {name} has not added");
                    return BadRequest(new
                    {
                        error = $"role {name} has not added "
                    });
                }
            }

            return BadRequest(new { error = "Role already exist" });
        }

        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            return Ok(users);
        }
        [HttpPost]
        public async Task<IActionResult> AddUserRole(string email, string rolename)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogInformation($"User with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"user does not exist"
                });
            }

            var roleExist = await _roleManager.RoleExistsAsync(rolename);
            if (!roleExist)
            {
                _logger.LogInformation($"User with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"user does not exist"
                });
            }

            var result = await _userManager.AddToRoleAsync(user, rolename);
            if (result.Succeeded)
            {
                return Ok(new
                {
                    result = "Success! User has been added to the role"
                });
            }
            else
            {
                _logger.LogInformation($"User was not added to the role");
                return BadRequest(new
                {
                    error = $"User was not added to the role"
                });
            }
        }
        [HttpGet]
        public async Task<IActionResult> GetUserRole(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogInformation($"User with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"user does not exist"
                });
            }

            var roles = await _userManager.GetRolesAsync(user);
            return Ok(roles);
        }

        [HttpPost]
        public async Task<IActionResult> RemoveUserRole(string email, string rolename)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogInformation($"User with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"user does not exist"
                });
            }

            var roleExist = await _roleManager.RoleExistsAsync(rolename);
            if (!roleExist)
            {
                _logger.LogInformation($"User with the {email} does not exist");
                return BadRequest(new
                {
                    error = $"user does not exist"
                });
            }
            var result = await _userManager.RemoveFromRoleAsync(user, rolename);
            if (result.Succeeded)
            {
                return Ok(new
                {
                    result = $"user {email} has been removed from role {rolename}"
                });
            }
            return BadRequest(new
            {
                error = $"Unable to remove User {email} from role{rolename}"
            });
        }
    }
}
