using DocumentManager.Entity;
using DocumentManager.Filter;
using DocumentManager.Helper;
using System;
using System.Net;
using System.Net.Http;
using System.ServiceModel.Channels;
using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;

namespace DocumentManager.Controllers
{
    [EnableCors(origins: "*", headers: "*", methods: "*", SupportsCredentials = true)]
    public class ExternalController : ApiController
    {

        [HttpPost]
        [AllowAnonymous]
        [Route("api/externaluser/gettoken/")]
        public HttpResponseMessage GetToken([FromBody]ExternalRequestEntity userData)
        {
            if (!string.IsNullOrEmpty(userData.ClientID) && !string.IsNullOrEmpty(userData.ClientKey))
            {
                var token = TokenHelper.GenerateToken(userData.ClientID, "ExternalClient");
                return Request.CreateResponse(HttpStatusCode.OK, token);
            }
            else
            {
                return Request.CreateResponse(HttpStatusCode.Unauthorized, "Client data invalid, request un-authrorized. Key and Id mandatory");
            }
        }


        [HttpPost]
        [ExternalTokenAuthenticate]
        [Route("api/externaluser/config/")]
        public HttpResponseMessage TestExternalClient()
        {
            return Request.CreateResponse(HttpStatusCode.OK, "Config data + random GUID " + Guid.NewGuid().ToString());
        }


        #region Private Methods


        private string GetClientIp(HttpRequestMessage request = null)
        {
            request = request ?? Request;

            if (request.Properties.ContainsKey("MS_HttpContext"))
            {
                return ((HttpContextWrapper)request.Properties["MS_HttpContext"]).Request.UserHostAddress;
            }
            else if (request.Properties.ContainsKey(RemoteEndpointMessageProperty.Name))
            {
                RemoteEndpointMessageProperty prop = (RemoteEndpointMessageProperty)request.Properties[RemoteEndpointMessageProperty.Name];
                return prop.Address;
            }
            else if (HttpContext.Current != null)
            {
                return HttpContext.Current.Request.UserHostAddress;
            }
            else
            {
                return null;
            }
        }
        #endregion

    }
}
