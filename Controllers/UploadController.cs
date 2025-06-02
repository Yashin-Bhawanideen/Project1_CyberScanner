using Grpc.Core;
using Microsoft.AspNetCore.Mvc;

namespace CyberSecurityThreatDetector.Controllers
{
    public class UploadController : Controller
    {
        //this is the API key of VirusTotal which allows us to upload a file and it is used to scan if the file is not protected or has malware

        private const string VirusTotalApiKey = "5887f76f6b22d188359a52487d4f2aad40e3163a0fea5feff6d9eb1bef4df9ad"; // Add your VirusTotal API key

        // GET: File/Upload
        public ActionResult Index()
        {
            return View();
        }

        /*this action is when the user uploads a file and clicks the upload file button, it 
         redircts them to their file explorer to select a file of their choice
         */

        [HttpPost]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            if (file != null && file.Length > 0)
            {
                var fileName = Path.GetFileName(file.FileName);
                var uploadPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Uploads");
                Directory.CreateDirectory(uploadPath);

                var fullPath = Path.Combine(uploadPath, fileName);

                using (var stream = new FileStream(fullPath, FileMode.Create))
                {
                    file.CopyTo(stream); // Save the file
                }

                TempData["SuccessMessage"] = "File uploaded successfully.";

                // Scan the file using VirusTotal
                using (var stream = new FileStream(fullPath, FileMode.Open))
                {
                    string scanId = await UploadFileToVirusTotal(stream, file.FileName);
                    

                    //if scanner is scanning and the file is not safe then this pops up, error message
                    if (scanId != null)
                    {
                        var result = await GetScanResult(scanId);
                        if (result != null)
                        {
                            if (result.Item1)
                                TempData["ScanResult"] = $"⚠️ Malicious file detected by {result.Item2} engines.";
                            else
                                TempData["ScanResult"] = "✅ File appears clean.";
                        }
                        else
                        {
                            TempData["ScanResult"] = "❗ Scan failed to retrieve results.";
                        }
                    }
                    else
                    {
                        TempData["ScanResult"] = "❗ Failed to upload file to VirusTotal.";
                    }
                }
            }
            else
            {
                TempData["ErrorMessage"] = "Please select a file to upload.";
            }

            return RedirectToAction("Index");
        }


        //this method uploads the file to VirusTotal and returns the scan ID
        private async Task<string> UploadFileToVirusTotal(Stream fileStream, string fileName)
        {
            using var client = new HttpClient();
            using var content = new MultipartFormDataContent();
            content.Add(new StreamContent(fileStream), "file", fileName);
            client.DefaultRequestHeaders.Add("x-apikey", VirusTotalApiKey);

            var response = await client.PostAsync("https://www.virustotal.com/api/v3/files", content);
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync();
            var obj = Newtonsoft.Json.Linq.JObject.Parse(json);
            return obj["data"]?["id"]?.ToString();
        }

        //this method retrieves the scan result from VirusTotal using the scan ID
        private async Task<Tuple<bool, int>> GetScanResult(string scanId)
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("x-apikey", VirusTotalApiKey);

            await Task.Delay(5000); // Wait for scan to complete
            var response = await client.GetAsync($"https://www.virustotal.com/api/v3/analyses/{scanId}");
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync();
            var obj = Newtonsoft.Json.Linq.JObject.Parse(json);

            var stats = obj["data"]?["attributes"]?["stats"];
            if (stats == null) return null;

            int malicious = (int)stats["malicious"];
            return new Tuple<bool, int>(malicious > 0, malicious);
        }
    }
}
