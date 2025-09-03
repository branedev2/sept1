using System;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Antiforgery;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace CsrfVulnerabilityExamples
{
    // True Positives (Vulnerable Code)

    public class BadController1 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPost]
        public ActionResult bad_case_1(string username)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: POST method that changes state without antiforgery token validation
            var db = new UserDatabase();
            db.UpdateUsername(User.Identity.Name, username);
            return RedirectToAction("Profile");
        }
// {/fact}
    }

    public class BadController2 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPut]
        public ActionResult bad_case_2(UserModel model)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: PUT method that changes state without antiforgery token validation
            if (ModelState.IsValid)
            {
                var service = new UserService();
                service.UpdateUser(model);
                return Json(new { success = true });
            }
            return Json(new { success = false });
        }
// {/fact}
    }

    public class BadController3 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpDelete]
        public ActionResult bad_case_3(int id)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: DELETE method that changes state without antiforgery token validation
            var productService = new ProductService();
            productService.DeleteProduct(id);
            return RedirectToAction("Index");
        }
// {/fact}
    }

    public class BadController4 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult bad_case_4([FromBody] PaymentInfo payment)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: Core MVC POST method that changes state without antiforgery token validation
            var paymentProcessor = new PaymentProcessor();
            paymentProcessor.ProcessPayment(payment);
            return Ok(new { status = "success" });
        }
// {/fact}
    }

    public class BadController5 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [Microsoft.AspNetCore.Mvc.HttpPatch]
        public IActionResult bad_case_5([FromBody] PartialUserUpdate update)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: PATCH method that changes state without antiforgery token validation
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
                
            var userService = new UserService();
            userService.PartialUpdate(update);
            return Ok();
        }
// {/fact}
    }

    [ApiController]
    [Route("api/[controller]")]
    public class BadController6 : ControllerBase
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPost("transfer")]
        public IActionResult bad_case_6([FromBody] TransferRequest request)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: API controller with POST method that changes state without antiforgery token validation
            var bankService = new BankService();
            bankService.TransferFunds(request.FromAccount, request.ToAccount, request.Amount);
            return Ok(new { message = "Transfer successful" });
        }
// {/fact}
    }

    public class BadController7 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPost]
        [Authorize]
        public ActionResult bad_case_7(PasswordChangeModel model)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: Even with authorization, still needs antiforgery protection
            if (ModelState.IsValid)
            {
                var userManager = new UserManager();
                userManager.ChangePassword(User.Identity.Name, model.NewPassword);
                return RedirectToAction("Profile");
            }
            return View(model);
        }
// {/fact}
    }

    public class BadController8 : Microsoft.AspNetCore.Mvc.Controller
    {
        private readonly IEmailService _emailService;

        public BadController8(IEmailService emailService)
        {
            _emailService = emailService;
        }
// {fact rule=coral-csrf-rule@v1.0 defects=1}

        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult bad_case_8([FromForm] ContactFormModel model)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: POST method that sends emails without antiforgery protection
            if (!ModelState.IsValid)
                return View(model);
                
            _emailService.SendContactEmail(model.Email, model.Subject, model.Message);
            return RedirectToAction("ThankYou");
        }
// {/fact}
    }

    public class BadController9 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPost]
        public JsonResult bad_case_9(int productId, int quantity)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: JSON result from POST without antiforgery protection
            var cartService = new ShoppingCartService();
            cartService.AddToCart(User.Identity.Name, productId, quantity);
            return Json(new { success = true });
        }
// {/fact}
    }

    public class BadController10 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        [Consumes("application/x-www-form-urlencoded")]
        public IActionResult bad_case_10([FromForm] SubscriptionModel model)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: Explicitly accepting form data without antiforgery protection
            var subscriptionService = new SubscriptionService();
            subscriptionService.Subscribe(model.Email, model.PlanId);
            return RedirectToAction("SubscriptionConfirmed");
        }
// {/fact}
    }

    public class BadController11 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPost]
        [Route("api/comments/create")]
        public ActionResult bad_case_11([FromBody] CommentModel comment)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: API-style route in traditional controller without antiforgery protection
            var commentService = new CommentService();
            commentService.AddComment(comment);
            return Json(new { success = true, commentId = comment.Id });
        }
// {/fact}
    }

    [ApiController]
    public class BadController12 : ControllerBase
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPut("users/{id}")]
        public IActionResult bad_case_12(int id, [FromBody] UserUpdateModel model)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: PUT endpoint without antiforgery protection
            var userService = new UserService();
            userService.UpdateUser(id, model);
            return NoContent();
        }
// {/fact}
    }

    public class BadController13 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        [AllowAnonymous] // Makes it even more vulnerable
        public IActionResult bad_case_13([FromForm] ResetPasswordModel model)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: Anonymous access to state-changing operation without antiforgery protection
            if (!ModelState.IsValid)
                return View(model);
                
            var passwordService = new PasswordService();
            passwordService.ResetPassword(model.Token, model.NewPassword);
            return RedirectToAction("Login");
        }
// {/fact}
    }

    public class BadController14 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [HttpPost]
        public async Task<ActionResult> bad_case_14(SettingsModel model)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: Async POST method without antiforgery protection
            if (ModelState.IsValid)
            {
                var settingsService = new UserSettingsService();
                await settingsService.UpdateSettingsAsync(User.Identity.Name, model);
                return RedirectToAction("Settings");
            }
            return View(model);
        }
// {/fact}
    }

    public class BadController15 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        [Produces("application/json")]
        public IActionResult bad_case_15([FromBody] OrderModel order)
        {
            // ruleid: mvc-missing-antiforgery
            // Vulnerable: JSON-producing endpoint without antiforgery protection
            var orderService = new OrderService();
            var result = orderService.PlaceOrder(order);
            return Ok(new { orderId = result.OrderId });
        }
// {/fact}
    }

    // True Negatives (Secure Code)

    public class GoodController1 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult good_case_1(string username)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Uses ValidateAntiForgeryToken attribute
            var db = new UserDatabase();
            db.UpdateUsername(User.Identity.Name, username);
            return RedirectToAction("Profile");
        }
// {/fact}
    }

    public class GoodController2 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [Microsoft.AspNetCore.Mvc.HttpPut]
        [ValidateAntiForgeryToken]
        public IActionResult good_case_2([FromBody] UserModel model)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Uses ValidateAntiForgeryToken attribute with PUT method
            if (ModelState.IsValid)
            {
                var service = new UserService();
                service.UpdateUser(model);
                return Json(new { success = true });
            }
            return Json(new { success = false });
        }
// {/fact}
    }

    public class GoodController3 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [HttpDelete]
        [ValidateAntiForgeryToken]
        public ActionResult good_case_3(int id)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Uses ValidateAntiForgeryToken attribute with DELETE method
            var productService = new ProductService();
            productService.DeleteProduct(id);
            return RedirectToAction("Index");
        }
// {/fact}
    }

    [AutoValidateAntiforgeryToken]
    public class GoodController4 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        public IActionResult good_case_4([FromBody] PaymentInfo payment)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Controller has AutoValidateAntiforgeryToken attribute
            var paymentProcessor = new PaymentProcessor();
            paymentProcessor.ProcessPayment(payment);
            return Ok(new { status = "success" });
        }
// {/fact}
    }

    public class GoodController5 : Microsoft.AspNetCore.Mvc.Controller
    {
        private readonly IAntiforgery _antiforgery;

        public GoodController5(IAntiforgery antiforgery)
        {
            _antiforgery = antiforgery;
        }
// {fact rule=coral-csrf-rule@v1.0 defects=0}

        [Microsoft.AspNetCore.Mvc.HttpPatch]
        public IActionResult good_case_5([FromBody] PartialUserUpdate update)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Manually validates antiforgery token
            _antiforgery.ValidateRequestAsync(HttpContext).GetAwaiter().GetResult();
            
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
                
            var userService = new UserService();
            userService.PartialUpdate(update);
            return Ok();
        }
// {/fact}
    }

    [ApiController]
    [Route("api/[controller]")]
    public class GoodController6 : ControllerBase
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [HttpPost("transfer")]
        [ValidateAntiForgeryToken]
        public IActionResult good_case_6([FromBody] TransferRequest request)
        {
            // ok: mvc-missing-antiforgery
            // Secure: API controller with ValidateAntiForgeryToken attribute
            var bankService = new BankService();
            bankService.TransferFunds(request.FromAccount, request.ToAccount, request.Amount);
            return Ok(new { message = "Transfer successful" });
        }
// {/fact}
    }

    public class GoodController7 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        [Consumes("application/json")]
        public IActionResult good_case_7([FromBody] PasswordChangeModel model)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Uses strict content-type checking (application/json)
            if (ModelState.IsValid)
            {
                var userManager = new UserManager();
                userManager.ChangePassword(User.Identity.Name, model.NewPassword);
                return RedirectToAction("Profile");
            }
            return View(model);
        }
// {/fact}
    }

    public class GoodController8 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [HttpGet] // Not a state-changing method
        public ActionResult good_case_8(int id)
        {
            // ok: mvc-missing-antiforgery
            // Secure: GET method doesn't change state, no need for antiforgery token
            var productService = new ProductService();
            var product = productService.GetProduct(id);
            return View(product);
        }
// {/fact}
    }

    public class GoodController9 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        [IgnoreAntiforgeryToken] // Explicitly ignoring, but using API key authentication instead
        public IActionResult good_case_9([FromHeader(Name = "X-API-Key")] string apiKey, [FromBody] OrderModel order)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Using API key authentication instead of antiforgery token
            if (string.IsNullOrEmpty(apiKey) || !ApiKeyValidator.IsValid(apiKey))
                return Unauthorized();
                
            var orderService = new OrderService();
            var result = orderService.PlaceOrder(order);
            return Ok(new { orderId = result.OrderId });
        }
// {/fact}
    }

    [ApiController]
    [Route("api/[controller]")]
    public class GoodController10 : ControllerBase
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [HttpPost]
        [Consumes("application/json")]
        public IActionResult good_case_10([FromBody] CommentModel comment)
        {
            // ok: mvc-missing-antiforgery
            // Secure: API controller with strict content-type checking
            var commentService = new CommentService();
            commentService.AddComment(comment);
            return CreatedAtAction(nameof(GetComment), new { id = comment.Id }, comment);
        }
// {/fact}

        [HttpGet("{id}")]
        public IActionResult GetComment(int id)
        {
            var commentService = new CommentService();
            var comment = commentService.GetComment(id);
            if (comment == null)
                return NotFound();
            return Ok(comment);
        }
    }

    public class GoodController11 : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> good_case_11(SettingsModel model)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Async method with ValidateAntiForgeryToken attribute
            if (ModelState.IsValid)
            {
                var settingsService = new UserSettingsService();
                await settingsService.UpdateSettingsAsync(User.Identity.Name, model);
                return RedirectToAction("Settings");
            }
            return View(model);
        }
    }

    [AutoValidateAntiforgeryToken]
    public class GoodController12 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [Microsoft.AspNetCore.Mvc.HttpPut]
        [AllowAnonymous]
        public IActionResult good_case_12([FromBody] UserUpdateModel model)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Even with AllowAnonymous, the controller has AutoValidateAntiforgeryToken
            var userService = new UserService();
            userService.UpdateUser(model.Id, model);
            return NoContent();
        }
// {/fact}
    }

    public class GoodController13 : Controller
    {
        private readonly IAntiforgery _antiforgery;

        public GoodController13(IAntiforgery antiforgery)
        {
            _antiforgery = antiforgery;
        }
// {fact rule=coral-csrf-rule@v1.0 defects=0}

        [HttpPost]
        public IActionResult good_case_13([FromForm] ResetPasswordModel model, [FromHeader(Name = "RequestVerificationToken")] string requestToken)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Manually validates antiforgery token from header
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            if (tokens.RequestToken != requestToken)
                return BadRequest("Invalid antiforgery token");
                
            var passwordService = new PasswordService();
            passwordService.ResetPassword(model.Token, model.NewPassword);
            return RedirectToAction("Login");
        }
// {/fact}
    }

    public class GoodController14 : Microsoft.AspNetCore.Mvc.Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [Microsoft.AspNetCore.Mvc.HttpPost]
        [ValidateAntiForgeryToken]
        [Produces("application/json")]
        public IActionResult good_case_14([FromBody] OrderModel order)
        {
            // ok: mvc-missing-antiforgery
            // Secure: JSON-producing endpoint with antiforgery protection
            var orderService = new OrderService();
            var result = orderService.PlaceOrder(order);
            return Ok(new { orderId = result.OrderId });
        }
// {/fact}
    }

    public class GoodController15 : Controller
    {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        [AcceptVerbs("POST", "PUT", "DELETE")]
        [ValidateAntiForgeryToken]
        public ActionResult good_case_15(AdminActionModel model)
        {
            // ok: mvc-missing-antiforgery
            // Secure: Multiple HTTP verbs with ValidateAntiForgeryToken attribute
            var adminService = new AdminService();
            adminService.PerformAction(model);
            return RedirectToAction("Dashboard");
        }
// {/fact}
    }

    // Helper classes to make the examples compile
    public class UserDatabase
    {
        public void UpdateUsername(string identity, string username) { }
    }

    public class UserService
    {
        public void UpdateUser(UserModel model) { }
        public void PartialUpdate(PartialUserUpdate update) { }
        public void UpdateUser(int id, UserUpdateModel model) { }
    }

    public class ProductService
    {
        public void DeleteProduct(int id) { }
        public object GetProduct(int id) { return null; }
    }

    public class PaymentProcessor
    {
        public void ProcessPayment(PaymentInfo payment) { }
    }

    public class BankService
    {
        public void TransferFunds(string fromAccount, string toAccount, decimal amount) { }
    }

    public class UserManager
    {
        public void ChangePassword(string name, string newPassword) { }
    }

    public class IEmailService
    {
        public void SendContactEmail(string email, string subject, string message) { }
    }

    public class ShoppingCartService
    {
        public void AddToCart(string name, int productId, int quantity) { }
    }

    public class SubscriptionService
    {
        public void Subscribe(string email, string planId) { }
    }

    public class CommentService
    {
        public void AddComment(CommentModel comment) { }
        public CommentModel GetComment(int id) { return null; }
    }

    public class PasswordService
    {
        public void ResetPassword(string token, string newPassword) { }
    }

    public class UserSettingsService
    {
        public Task UpdateSettingsAsync(string name, SettingsModel model) { return Task.CompletedTask; }
    }

    public class OrderService
    {
        public OrderResult PlaceOrder(OrderModel order) { return new OrderResult(); }
    }

    public class AdminService
    {
        public void PerformAction(AdminActionModel model) { }
    }

    public static class ApiKeyValidator
    {
        public static bool IsValid(string apiKey) { return true; }
    }

    // Model classes
    public class UserModel { }
    public class PartialUserUpdate { }
    public class TransferRequest
    {
        public string FromAccount { get; set; }
        public string ToAccount { get; set; }
        public decimal Amount { get; set; }
    }
    public class PasswordChangeModel
    {
        public string NewPassword { get; set; }
    }
    public class ContactFormModel
    {
        public string Email { get; set; }
        public string Subject { get; set; }
        public string Message { get; set; }
    }
    public class SubscriptionModel
    {
        public string Email { get; set; }
        public string PlanId { get; set; }
    }
    public class CommentModel
    {
        public int Id { get; set; }
    }
    public class ResetPasswordModel
    {
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }
    public class SettingsModel { }
    public class OrderModel { }
    public class OrderResult
    {
        public string OrderId { get; set; }
    }
    public class PaymentInfo { }
    public class UserUpdateModel
    {
        public int Id { get; set; }
    }
    public class AdminActionModel { }
}