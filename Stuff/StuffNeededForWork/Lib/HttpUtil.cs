//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Net;

namespace StuffNeededForWork.Lib
{
    class HttpUtil
    {
        public static bool UrlExists(string url, string authType = "Negotiate")
        {
            var request = WebRequest.Create(url);

            var credcache = new CredentialCache();
            credcache.Add(new Uri(url), authType, CredentialCache.DefaultNetworkCredentials);
            request.Credentials = credcache;

            request.Timeout = 3000;

            try
            {
                using var response = (HttpWebResponse)request.GetResponse();
                return response.StatusCode == HttpStatusCode.OK;
            }
            catch (WebException)
            {
            }

            return false;
        }
    }
}
