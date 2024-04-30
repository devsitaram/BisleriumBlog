using BisleriumBlog.Application.DTOs;

namespace BisleriumBlog.Application.Common.Interface
{
    public interface IAuthentication
    {
        Task<ResponseDTO> Register(UserRegisterRequestDto model);
        Task<LoginResponseDTO> Login(UserLoginRequestDTO model);
        Task<ResponseDTO> ForgotPassword(string email, string password);
        Task<UserDetailsDTO> GetUserProfile();
        Task<UserDetailsDTO> UpdateProfile();
        Task<IEnumerable<UserDetailsDTO>> GetUserDetails();
    }
}
