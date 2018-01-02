using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace DocumentManager.Helper
{
    public class JwtVerifyHelper
    {

        public string Secret = ConfigurationManager.AppSettings["secretkey"].ToString();

        private ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

                if (jwtToken == null)
                    return null;

                var symmetricKey = Convert.FromBase64String(Secret);

                var validationParameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateLifetime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(symmetricKey),
                    ClockSkew = new TimeSpan(0, 1, 0)
                };

                SecurityToken securityToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out securityToken);

                return principal;
            }

            catch (Exception ex)
            {
                return null;
            }
        }


        public bool ValidateToken(string token, out string role, out string username)
        {
            role = null;
            username = "";

            var simplePrinciple = this.GetPrincipal(token);

            if (null == simplePrinciple)
                return false;

            var identity = simplePrinciple.Identity as ClaimsIdentity;

            if (identity == null)
                return false;

            if (!identity.IsAuthenticated)
                return false;

            var roleClaim = identity.FindFirst(x => x.Type == ClaimTypes.Role);
            var usernameClaim = identity.FindFirst(x => x.Type == ClaimTypes.Name);
            role = roleClaim?.Value;
            username = usernameClaim?.Value;

            if (string.IsNullOrEmpty(role))
                return false;

            // TODO :: Check the status of token :: for Added security

            return true;
        }

    }
}