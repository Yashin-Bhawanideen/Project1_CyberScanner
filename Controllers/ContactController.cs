using Microsoft.AspNetCore.Mvc;

namespace CyberSecurityThreatDetector.Controllers
{
    public class ContactController : Controller
    {
        //the action is taken back to the view for contact tab
        public IActionResult Index()
        {
            return View();
        }
    }
}
