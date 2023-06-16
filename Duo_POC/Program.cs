using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Net;
using System.IO;
using System.Text.RegularExpressions;

using System.Globalization;
public class DuoAPI
{
    public string integrationKey = "xxxx";
    public string secretKey = "xxxxx";
    public string apiHost = "xxxxx";
    public string username = "AAA_CBTEST";
    public string adGUID = "xxxxxx";
}
class Program
{
    DuoAPI d = new DuoAPI();
    static void Main()
    {

        DuoAPI dapi = new DuoAPI();
        // Generate the timestamp in RFC 2822 format
        string timestamp = DateTimeOffset.UtcNow.ToString("ddd, dd MMM yyyy HH:mm:ss zz00");
        string response = "";
        Dictionary<string,string> dparam = new Dictionary<string, string>();
        //dparam.Add("email", "AAA_CBTEST@warwickshire.ac.uk");
        //dparam.Add("device", "DPEGTXRNQE3P6TWU45ZU");
        //dparam.Add("factor", "push");
        dparam.Add("username", "CBUCK");
        //dparam.Add("valid_secs", "2592000");

                Program p = new Program();
        response = p.ApiCall("POST", "/admin/v1/users/directorysync/" + dapi.adGUID + "/syncuser", dparam,Convert.ToDateTime(DateTimeOffset.Parse(timestamp).UtcDateTime));
        //response=p.ApiCall("POST", "/auth/v2/auth", dparam,Convert.ToDateTime(DateTimeOffset.Parse(timestamp).UtcDateTime));
        //response = p.ApiCall("GET", "/admin/v1/users/DUPBFN0PCOMOQTURSY8G/phones", dparam, Convert.ToDateTime(DateTimeOffset.Parse(timestamp).UtcDateTime));
        //response = p.ApiCall("GET", "/admin/v1/users", new Dictionary<string,string>(), Convert.ToDateTime(DateTimeOffset.Parse(timestamp).UtcDateTime));

        /*
                // Create the request body
                var data = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("username", username),
                };

                var formData = new Dictionary<string, string>
                {
                    { "username", username }
                };

                var encodedFormData = new FormUrlEncodedContent(formData);
                var encodedString = encodedFormData.ReadAsStringAsync().Result;
                //encodedString = "75%73%65%72%6E%61%6D%65%3D%41%41%41%5F%43%42%54%45%53%54";
                // Convert the data to JSON
                string jsonData = Newtonsoft.Json.JsonConvert.SerializeObject(data);
                StringContent jData = new StringContent(jsonData);
                // Create the URL-encoded form data
                //string formData =   $"username={Uri.EscapeDataString(username)}";
                // Generate the signature
                string signature = GenerateSignature(secretKey, timestamp, "GET", "/admin/v1/users/directorysync/" + adGUID + "/syncuser", apiHost, encodedString);

                //var content = new StringContent(formData, Encoding.UTF8, "application/x-www-form-urlencoded");
                // Send the request
                using (var client = new HttpClient())
                {
                    client.BaseAddress = new Uri($"https://{apiHost}");


                    client.DefaultRequestHeaders.Add("Authorization", $"Basic {GetEncodedCredentials(integrationKey, secretKey)}");
                    client.DefaultRequestHeaders.Add("X-Duo-Date", timestamp);
                    client.DefaultRequestHeaders.Add("Host", apiHost);
                    client.DefaultRequestHeaders.Add("User-Agent", "Duo API Client");

                    var response = client.PostAsync("/admin/v1/users", encodedFormData).Result;
                    var responseContent = response.Content.ReadAsStringAsync().Result;

                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("User synchronized successfully!");
                        Console.WriteLine(responseContent);
                    }
                    else
                    {
                        Console.WriteLine("Failed to synchronize user:");
                        Console.WriteLine(responseContent);
                    }
                }

                Console.ReadLine();*/
    }

    static string GenerateSignature(string secretKey, string timestamp, string method, string path, string host, string kvp)
    {
        //timestamp = timestamp.Replace("GMT", "-0000");
        string canon = $"{timestamp}\n{method.ToUpper()}\n{host}\n{path}{kvp}";
        using (var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secretKey)))
        {
            return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(canon)));
        }
    }

    static string GetEncodedCredentials(string integrationKey, string secretKey)
    {
        string credentials = $"{integrationKey}:{secretKey}";
        byte[] credentialsBytes = Encoding.UTF8.GetBytes(credentials);
        return Convert.ToBase64String(credentialsBytes);
    }

    private string HmacSign(string data)
    {
        byte[] key_bytes = ASCIIEncoding.ASCII.GetBytes(d.secretKey);
        HMACSHA512 hmac = new HMACSHA512(key_bytes);

        byte[] data_bytes = ASCIIEncoding.ASCII.GetBytes(data);
        hmac.ComputeHash(data_bytes);

        string hex = BitConverter.ToString(hmac.Hash);
        return hex.Replace("-", "").ToLower();
    }

    protected string CanonicalizeRequest(string method,
                                             string path,
                                             string canon_params,
                                             string date)
    {
        string[] lines = {
                date,
                method.ToUpperInvariant(),
                d.apiHost.ToLower(),
                path,
                canon_params,
            };
        string canon = String.Join("\n",
                                   lines);
        return canon;
    }

    public string Sign(string method,
                           string path,
                           string canon_params,
                           string date)
    {
        string canon = this.CanonicalizeRequest(method,
                                                path,
                                                canon_params,
                                                date);
        string sig = this.HmacSign(canon);
        string auth = d.integrationKey + ':' + sig;
        return "Basic " + Encode64(auth);
    }

    private static string Encode64(string plaintext)
    {
        byte[] plaintext_bytes = ASCIIEncoding.ASCII.GetBytes(plaintext);
        string encoded = System.Convert.ToBase64String(plaintext_bytes);
        return encoded;
    }

    public static string FinishCanonicalize(string p)
    {
        // Signatures require upper-case hex digits.
        p = Regex.Replace(p,
                        "(%[0-9A-Fa-f][0-9A-Fa-f])",
                        c => c.Value.ToUpperInvariant());
        // Escape only the expected characters.
        p = Regex.Replace(p,
                        "([!'()*])",
                        c => "%" + Convert.ToByte(c.Value[0]).ToString("X"));
        p = p.Replace("%7E", "~");
        // UrlEncode converts space (" ") to "+". The
        // signature algorithm requires "%20" instead. Actual
        // + has already been replaced with %2B.
        p = p.Replace("+", "%20");
        return p;
    }

    public static string CanonicalizeParams(Dictionary<string, string> parameters)
    {
        var ret = new List<String>();
        foreach (KeyValuePair<string, string> pair in parameters)
        {
            string p = String.Format("{0}={1}",
                                     HttpUtility.UrlEncode(pair.Key),
                                     HttpUtility.UrlEncode(pair.Value));

            p = FinishCanonicalize(p);
            ret.Add(p);
        }
        ret.Sort(StringComparer.Ordinal);
        return string.Join("&", ret.ToArray());
    }


    // handle value as an object eg. next_offset = ["123", "fdajkld"]
    public static string CanonicalizeParams(Dictionary<string, object> parameters)
    {
        var ret = new List<String>();
        foreach (KeyValuePair<string, object> pair in parameters)
        {
            string p = "";
            if (pair.Value.GetType() == typeof(string[]))
            {
                string[] values = (string[])pair.Value;
                string value1 = values[0];
                string value2 = values[1];
                p = String.Format("{0}={1}&{2}={3}",
                                    HttpUtility.UrlEncode(pair.Key),
                                    HttpUtility.UrlEncode(value1),
                                    HttpUtility.UrlEncode(pair.Key),
                                    HttpUtility.UrlEncode(value2));
            }
            else
            {
                string val = (string)pair.Value;
                p = String.Format("{0}={1}",
                                    HttpUtility.UrlEncode(pair.Key),
                                    HttpUtility.UrlEncode(val));
            }
            p = FinishCanonicalize(p);
            ret.Add(p);
        }
        ret.Sort(StringComparer.Ordinal);
        return string.Join("&", ret.ToArray());
    }
    public  string ApiCall(string method,
                              string path,
                              Dictionary<string, string> parameters,                              
                              DateTime date)
    {
        string canon_params = CanonicalizeParams(parameters);
        string query = "";
        if (!method.Equals("POST") && !method.Equals("PUT"))
        {
            if (parameters.Count > 0)
            {
                query = "?" + canon_params;
            }
        }
        string url = string.Format("{0}://{1}{2}{3}",
                                   "https",
                                   d.apiHost,
                                   path,
                                   query);

        string date_string = DateToRFC822(date);
        string auth = Sign(method, path, canon_params, date_string);



        HttpWebResponse response = AttemptRetriableHttpRequest(
            method, url, auth, date_string, canon_params);
        StreamReader reader
            = new StreamReader(response.GetResponseStream());
        return reader.ReadToEnd();
    }

    private HttpWebResponse AttemptRetriableHttpRequest(
            String method, String url, String auth, String date, String cannonParams)
    {
        while (true)
        {
            // Do the request and process the result.
            HttpWebRequest request = PrepareHttpRequest(method, url, auth, date, cannonParams);
            HttpWebResponse response;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (WebException ex)
            {
                response = (HttpWebResponse)ex.Response;
                if (response == null)
                {
                    throw;
                }
            }

            StreamReader reader
                = new StreamReader(response.GetResponseStream());
            string txt = reader.ReadToEnd();
            return response;
            

            
        }
    }
    private HttpWebRequest PrepareHttpRequest(String method, String url, String auth, String date,
            String cannonParams)
    {
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        //request.ServerCertificateValidationCallback = GetCertificatePinner();
        request.Method = method;
        request.Accept = "application/json";
        request.Headers.Add("Authorization", auth);
        request.Headers.Add("X-Duo-Date", date);
        //request.UserAgent = this.user_agent;
        // If no proxy, check for and use WinHTTP proxy as autoconfig won't pick this up when run from a service
        /*if (!HasProxyServer(request))
            request.Proxy = GetWinhttpProxy();
        */
        if (method.Equals("POST") || method.Equals("PUT"))
        {
            byte[] data = Encoding.UTF8.GetBytes(cannonParams);
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = data.Length;
            using (Stream requestStream = request.GetRequestStream())
            {
                requestStream.Write(data, 0, data.Length);
            }
        }
        
        return request;
    }

    private static string DateToRFC822(DateTime date)
    {
        // Can't use the "zzzz" format because it adds a ":"
        // between the offset's hours and minutes.
        string date_string = date.ToString(
            "ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture);
        int offset = 0;
        // set offset if input date is not UTC time.
        if (date.Kind != DateTimeKind.Utc)
        {
            offset = TimeZoneInfo.Local.GetUtcOffset(date).Hours;
        }
        string zone;
        // + or -, then 0-pad, then offset, then more 0-padding.
        if (offset < 0)
        {
            offset *= -1;
            zone = "-";
        }
        else
        {
            zone = "+";
        }
        zone += offset.ToString(CultureInfo.InvariantCulture).PadLeft(2, '0');
        date_string += " " + zone.PadRight(5, '0');
        return date_string;
    }

  /*  public string ApiCall(string method,
                              string path,
                              Dictionary<string, string> parameters,
                              int timeout,
                              out HttpStatusCode statusCode)
    {
        return ApiCall(method, path, parameters, 0, DateTime.UtcNow, out statusCode);
    }*/
}
