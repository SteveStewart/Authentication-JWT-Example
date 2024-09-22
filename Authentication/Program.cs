using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Authentication.Data;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Authentication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Configure Logging
            builder.Logging.ClearProviders();
            builder.Logging.AddConsole();
            builder.Logging.AddDebug();

            // Configure Database
            var connectionString = builder.Configuration.GetConnectionString("AuthenticationContextConnection")
                ?? throw new InvalidOperationException("Connection string 'AuthenticationContextConnection' not found.");

            builder.Services.AddDbContext<AuthenticationContext>(options => options.UseSqlServer(connectionString));

            // Configure Identity
            builder.Services.AddIdentity<IdentityUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<AuthenticationContext>()
                .AddDefaultTokenProviders();


            // Add Controllers with Views
            builder.Services.AddControllersWithViews();

            // Configure JWT Settings
            var jwtSettings = builder.Configuration.GetSection("Jwt");
            var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);

            // Configure Authentication
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings["Issuer"],
                    ValidAudience = jwtSettings["Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ClockSkew = TimeSpan.Zero
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        Console.WriteLine($"Token validated for: {context.Principal.Identity.Name}");
                        return Task.CompletedTask;
                    }
                };
            });

            // Add Authorization
            builder.Services.AddAuthorization();

            // Configure CORS
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                {
                    builder
                        .AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                });
            });

            builder.Services.AddRazorPages();
            var app = builder.Build();

            // Seed Roles and Admin User
            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
                var userManager = services.GetRequiredService<UserManager<IdentityUser>>();

                // Define roles
                string[] roles = { "ADMIN", "USER" };

                foreach (var role in roles)
                {
                    if (!roleManager.RoleExistsAsync(role).Result)
                    {
                        roleManager.CreateAsync(new IdentityRole(role)).Wait();
                    }
                }

                var adminUser = userManager.FindByNameAsync("admin@stewart.dev").Result;
                if (adminUser == null)
                {
                    adminUser = new IdentityUser
                    {
                        UserName = "admin@stewart.dev",
                        Email = "admin@stewart.dev",
                        EmailConfirmed = true
                    };
                    var result = userManager.CreateAsync(adminUser, "Password123-").Result;
                    if (result.Succeeded)
                    {
                        userManager.AddToRoleAsync(adminUser, "ADMIN").Wait();
                    }
                }

                var normalUser = userManager.FindByNameAsync("user@stewart.dev").Result;
                if (normalUser == null)
                {
                    normalUser = new IdentityUser
                    {
                        UserName = "user@stewart.dev",
                        Email = "user@stewart.dev",
                        EmailConfirmed = true
                    };
                    var result = userManager.CreateAsync(normalUser, "Password123-").Result;
                    if (result.Succeeded)
                    {
                        userManager.AddToRoleAsync(normalUser, "USER").Wait();
                    }
                }
            }

            // Configure Middleware Pipeline
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseCors("AllowAll");

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.MapRazorPages();
            app.Run();
        }
    }
}
