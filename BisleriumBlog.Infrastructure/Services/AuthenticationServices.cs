using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BisleriumBlog.Application.Common.Interface;
using BisleriumBlog.Application.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using BisleriumBlog.Domain.Entities;

namespace BisleriumBlog.Infrastructure.Services
{
    public class AuthenticationService : IAuthentication
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthenticationService(UserManager<User> userManager, IConfiguration configration, SignInManager<User> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configration;
            _roleManager = roleManager;
        }

        // Register
        public async Task<ResponseDTO> Register(UserRegisterRequestDto model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new ResponseDTO { Status = false, Message = "User already exists!" };

            User user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new ResponseDTO
                    { Status = false, Message = "Enter the valid password. Please check user details and try again." };

            // Assigning a role to the user
            if (!await _roleManager.RoleExistsAsync("Blogger"))
                await _roleManager.CreateAsync(new IdentityRole("Blogger"));

            await _userManager.AddToRoleAsync(user, "Blogger");

            return new ResponseDTO { Status = true, Message = "User created successfully!" };
        }

        // Login User
        public async Task<LoginResponseDTO> Login(UserLoginRequestDTO model)
        {

            var user = await _userManager.FindByNameAsync(model.Username);
            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, true, false);

            if (result.Succeeded)
            {
                var token = await CreateJwtAccessToken(user);

                return new LoginResponseDTO()
                {
                    Message = "Login successful",
                    Status = true,
                    AccessToken = token
                };
            }

            return new LoginResponseDTO()
            {
                Message = "User login failed! Please check user details and try again.!",
                Status = false
            };
        }

        public async Task<string> CreateJwtAccessToken(User user)
        {
            var signingCredentials = GetSigningCredentials();
            var claims = await GetClaims(user);
            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }

        private SigningCredentials GetSigningCredentials()
        {
            var jwtConfig = _configuration.GetSection("jwtConfig");
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["secret"]!));
            return new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
        }

        private async Task<List<Claim>> GetClaims(User user)
        {
            var claims = new List<Claim>
            {
                new Claim("id", user.Id),
                new Claim("username", user.UserName),
                new Claim("email", user.Email),
            };
            var roles = await _userManager.GetRolesAsync(user);

            foreach (var role in roles)
            {
                claims.Add(new Claim("role", role));
            }

            return claims;
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("jwtConfig");
            var tokenOptions = new JwtSecurityToken
            (
            issuer: jwtSettings["issuer"],
            audience: jwtSettings["audience"],
            claims: claims,
            expires: DateTime.Now.AddHours(Convert.ToDouble(jwtSettings["expiresIn"])),
            signingCredentials: signingCredentials
            );

            return tokenOptions;
        }



        [Authorize]
        public async Task<IEnumerable<UserDetailsDTO>> GetUserDetails()
        {
            var users = await _userManager.Users.Select(x => new
            {
                x.Email,
                x.UserName,
                x.EmailConfirmed
            }).ToListAsync();

            // either
            var userDetails = from userData in users
                              select new UserDetailsDTO()
                              {
                                  Email = userData.Email,
                                  UserName = userData.UserName,
                                  IsEmailConfirmed = userData.EmailConfirmed
                              };

            // OR
            var userDatas = new List<UserDetailsDTO>();
            foreach (var item in users)
            {
                userDatas.Add(new UserDetailsDTO()
                {
                    Email = item.Email,
                    UserName = item.UserName,
                    IsEmailConfirmed = item.EmailConfirmed
                });
            }

            return userDetails; // userDatas;
        }


        // Reset Password (Forgot Password)
        public async Task<ResponseDTO> ForgotPassword(string email, string newPassword)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new ResponseDTO { Status = false, Message = "User not found!" };

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
            if (!result.Succeeded)
                return new ResponseDTO { Status = false, Message = "Failed to reset password!" };

            return new ResponseDTO { Status = true, Message = "Password reset successfully!" };
        }

        // Get Profile details
        public async Task<UserDetailsDTO> GetUserProfile()
        {
            var userId = Guid.NewGuid().ToString();

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return null;
            }

            var userDetails = new UserDetailsDTO()
            {
                Email = user.Email,
                UserName = user.UserName,
                IsEmailConfirmed = user.EmailConfirmed
            };

            return userDetails;
        }

        public Task<UserDetailsDTO> UpdateProfile()
        {
            throw new NotImplementedException();
        }
    }
}
