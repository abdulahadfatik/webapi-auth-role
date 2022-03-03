using LearnApi.Data;
using LearnApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnApi.Controllers
{
    [Route("learnApi/[action]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles ="AppUser")]
    public class LearnApiController : Controller
    {
        private readonly ApiDbContext _context;

        public LearnApiController (ApiDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IActionResult> GetEmp()
        {
            var emp = await _context.Employees.ToListAsync();
            return Ok(emp);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetEmpID(int id)
        {
            var emp = await _context.Employees.FirstOrDefaultAsync(x => x.Id == id);

            if (emp == null)
            {
                return NotFound();
            }
            return Ok(emp);
        }

        [HttpPost]
        public async Task<IActionResult> CreateEmp(Employee data)
        {
            if(ModelState.IsValid)
            {
                await _context.Employees.AddAsync(data);
                //await _context.Database.ExecuteSqlCommand("SET IDENTITY_INSERT dbo.DestuffedContainer ON");
                await _context.SaveChangesAsync();

                return CreatedAtAction("GetEmp", new { data.Id }, data);
            }
            return new JsonResult("Somthing went wrong") { StatusCode = 500 };
         }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateEmp(int id, Employee employee)
        {
            if (id != employee.Id)
                return BadRequest();

            var existemp = await _context.Employees.FirstOrDefaultAsync(x => x.Id == id);

            if (existemp == null)
                return NotFound();

                existemp.Name = employee.Name;
                existemp.Email = employee.Email;
                existemp.Password = employee.Password;
                existemp.City = employee.City;

                await _context.SaveChangesAsync();
                return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteEmp(int id)
        {
            var empdel = await _context.Employees.FirstOrDefaultAsync(x => x.Id == id);

            if (empdel == null)
                return NotFound();

            _context.Employees.Remove(empdel);
            await _context.SaveChangesAsync();

            return Ok(empdel);
        }
    }
}
