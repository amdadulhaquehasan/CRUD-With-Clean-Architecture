using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;

namespace Application.Services;

public interface IAccountService
{
    Task CreateAdmin();
    
    Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model);
    
    Task<LoginResponse> LoginAccountAsync(LoginDTO model);
    
    Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model);
    
    Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model);
    
    Task<IEnumerable<GetUsersWithRolesResponseDTO>>  GetUsersWithRolesAsync();
    
    Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model);
}