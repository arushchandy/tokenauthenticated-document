using DocumentManager.Helper;
using System;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace DocumentManager.Filter
{
    public class ExternalTokenAuthenticateAttribute : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            var isAuthentic = false;
            var accessToken = GetAccessToken(actionContext);
            if (null != accessToken)
            {
                isAuthentic = ValidateFromToken(accessToken);
            }
            if (!isAuthentic)
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Forbidden, "Client data invalid, request un-authrorized.");
        }


        private bool ValidateFromToken(string token)
        {
            bool authentic = false;
            try
            {
                var jwtAuthenticate = new JwtVerifyHelper();
                string role = string.Empty;
                string username = string.Empty;
                authentic = jwtAuthenticate.ValidateToken(token, out role, out username);
                if (authentic && !string.IsNullOrEmpty(role))
                {
                    HttpContext.Current.Items.Add("Role", role);
                    HttpContext.Current.Items.Add("UserName", username);
                }
            }
            catch (Exception ex)
            {
                return false;
            }
            return authentic;
        }

        private string GetAccessToken(HttpActionContext actionContext)
        {
            string accessToken = null;
            var authHeader = actionContext.Request.Headers.Authorization;
            if (null != authHeader)
            {
                if (authHeader.Scheme.Equals("bearer", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(authHeader.Parameter))
                {
                    accessToken = authHeader.Parameter;
                }
            }
            return accessToken;
        }


    }
}