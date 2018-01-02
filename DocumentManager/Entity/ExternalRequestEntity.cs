using Newtonsoft.Json;

namespace DocumentManager.Entity
{
    public class ExternalRequestEntity
    {
        [JsonProperty("clientId")]
        public string ClientID { get; set; }

        [JsonProperty("clientKey")]
        public string ClientKey { get; set; }
    }
}