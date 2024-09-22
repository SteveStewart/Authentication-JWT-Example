using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Authentication.API
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class ProductController : ControllerBase
    {
        [HttpGet("GetProducts")]
        public IActionResult GetProducts()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = User.Identity.Name;

            var products = new string[] { "Product 1", "Product 2", "Product 3" };
            return Ok(new { UserId = userId, UserName = username, Products = products });
        }

        [HttpGet("GetAllProducts")]
        [Authorize(Roles = "ADMIN")]
        public IActionResult GetAllProducts()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = User.Identity.Name;

            // Retrieve all roles
            var roles = User.FindAll(ClaimTypes.Role).Select(r => r.Value).ToList();

            var products = new string[] { "Product 1", "Product 2", "Product 3", "Product 4 Discontinued" };
            return Ok(new { UserId = userId, Roles = roles, UserName = username, Products = products });
        }
    }
}
