//namespace CustomIdentityWithJwt.Controllers
//{
//    public class RoleSeeder
//    {
//    }
//}
using CustomIdentityWithJwt.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace CustomIdentityWithJwt.Services
{
    public class RoleSeederService
    {
        public static async Task SeedRoles(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Define role names
            string[] roleNames = { "Admin", "Customer", "Vendor", "Courier" };

            foreach (var roleName in roleNames)
            {
                // Check if the role exists
                var roleExists = await roleManager.RoleExistsAsync(roleName);

                if (!roleExists)
                {
                    // Create the role if it doesn't exist
                    var role = new IdentityRole(roleName);
                    await roleManager.CreateAsync(role);
                }
            }
        }
    }
}
