using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.DTOs.Request.Account;
using Application.DTOs.Response.Account;
using Microsoft.AspNetCore.Components.Authorization;

namespace Application.Extensions;

public class CustomAuthenticationStateProvider(LocalStorageService localStorageService) : AuthenticationStateProvider
{
    private readonly ClaimsPrincipal anonymous = new(new ClaimsIdentity());

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var tokenModel = await localStorageService.GetModelFromToken();
        if(string.IsNullOrEmpty(tokenModel.Token)) return await Task.FromResult(new AuthenticationState(anonymous));
        
        var getUserClaims = DecryptToken(tokenModel.Token!);
        if(getUserClaims == null) return await Task.FromResult(new AuthenticationState(anonymous));
        
        var claimsPrincipal = SetClaimPrincipal(getUserClaims);
        return await Task.FromResult(new AuthenticationState(claimsPrincipal));
    }

    public async Task UpdateAuthenticationState(LocalStorageDTO localStorageDto)
    {
        var claimsPrincipal = new ClaimsPrincipal();
        if (localStorageDto.Token != null || localStorageDto.Refresh != null)
        {
            await localStorageService.SetBrowserLocalStorage(localStorageDto);
            var getUserClaims = DecryptToken(localStorageDto.Token!);
            claimsPrincipal = SetClaimPrincipal(getUserClaims);
        }
        else
        {
            await localStorageService.RemoveTokenFromBrowserLocalStorage();
        }
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
    }

    public static ClaimsPrincipal SetClaimPrincipal(UserClaimsDTO claims)
    {
        if (claims.Email is null) return new ClaimsPrincipal();
        return new ClaimsPrincipal(new ClaimsIdentity([
            new(ClaimTypes.Name, claims.Username!),
            new(ClaimTypes.Email, claims.Email!),
            new(ClaimTypes.Role, claims.Role!),
            new Claim("Fullname", claims.Fullname)
        ], Constant.AuthenticationType));
    }

    private static UserClaimsDTO DecryptToken(string jwtToken)
    {
        try
        {
            if(string.IsNullOrEmpty(jwtToken)) return new UserClaimsDTO();

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtToken);
            
            var name = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Name)!.Value;
            var email = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Email)!.Value;
            var role = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Role)!.Value;
            var fullname = token.Claims.FirstOrDefault(_ => _.Type == "FullName")!.Value;
            return new UserClaimsDTO(fullname, name, email, role);
        }
        catch
        {
            return null!;
        }
    }
}