using Microsoft.IdentityModel.Tokens;
using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;


namespace DocumentManager.Helper
{
    public class TokenHelper
    {

        public static string GenerateToken(string userName, string role, string issuer = "", string audience = "")
        {
            string Secret = ConfigurationManager.AppSettings["secretkey"].ToString();
            string TokenTimeOut = ConfigurationManager.AppSettings["tokentimeout"].ToString();
            int TokenTimeOutVal = string.IsNullOrEmpty(TokenTimeOut) ? 90 : int.Parse(TokenTimeOut);
            var symmetricKey = Convert.FromBase64String(Secret);
            var tokenHandler = new JwtSecurityTokenHandler();

            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]{
                        new Claim(ClaimTypes.Name, userName),
                        new Claim(ClaimTypes.Role,role)
                    }),
                Expires = now.AddMinutes(Convert.ToInt32(TokenTimeOutVal)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(stoken);

            return token;


        }
    }
}