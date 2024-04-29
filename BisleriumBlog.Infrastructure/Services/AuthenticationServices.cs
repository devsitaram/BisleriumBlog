using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BisleriumBlog.Application.Common.Interface;
using BisleriumBlog.Application.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace BisleriumBlog.Infrastructure.Services
{
    public class AuthenticationService : IAuthentication
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthenticationService(UserManager<IdentityUser> userManager, IConfiguration configration, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configration;
        }

        // Regisster
        public async Task<ResponseDTO> Register(UserRegisterRequestDto model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new ResponseDTO { Status = "Error", Message = "User already exists!" };


            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                await _signInManager.Role ????
                return new ResponseDTO
                    { Status = "Error", Message = "User creation failed! Please check user details and try again." };

            return new ResponseDTO { Status = "Success", Message = "User created successfully!" };
        }

        // Login User
        public async Task<ResponseDTO> Login(UserLoginRequestDTO model)
        {

            var user = await _userManager.FindByNameAsync(model.Username);
            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, true, false);

            if (result.Succeeded)
            {
                var token = await CreateJwtAccessToken(user); // Method to generate the token

                return new ResponseDTO()
                {
                    Message = "Login successful",
                    Status = "Success",
                    Data = token
                };

            }

            return new ResponseDTO()
            {
                Message = "User login failed! Please check user details and try again.!",
                Status = "Error"
            };

        }

        // to provide token or POST request
        /*[AllowAnonymous]
        public string Get(string username, string password)
        {
            return JwtManager.GenerateToken(username);
        }*/

        public async Task<string> CreateJwtAccessToken(IdentityUser user)
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

        private async Task<List<Claim>> GetClaims(IdentityUser user)
        {
            var claims = new List<Claim>
            {
                new Claim("id", user.Id),
                new Claim("username", user.UserName),
                new Claim("email", user.Email),
                // new Claim("role", user.Email)
            };
            var roles = await _userManager.GetRolesAsync(user);

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
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
                return new ResponseDTO { Status = "Error", Message = "User not found!" };

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
            if (!result.Succeeded)
                return new ResponseDTO { Status = "Error", Message = "Failed to reset password!" };

            return new ResponseDTO { Status = "Success", Message = "Password reset successfully!" };
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
