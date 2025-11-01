using System;
using System.Collections.Generic;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace MassAssignmentVulnerabilityExamples
{
    // User model with sensitive properties
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public bool IsAdmin { get; set; }
        public decimal AccountBalance { get; set; }
    }

    // Product model with sensitive properties
    public class Product
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
        public decimal CostPrice { get; set; }
        public bool IsDiscontinued { get; set; }
    }

    // Order model with sensitive properties
    public class Order
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public decimal TotalAmount { get; set; }
        public bool IsApproved { get; set; }
        public decimal Discount { get; set; }
    }

    // Employee model with sensitive properties
    public class Employee
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Position { get; set; }
        public decimal Salary { get; set; }
        public bool IsManager { get; set; }
    }

    // Customer model with sensitive properties
    public class Customer
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public decimal CreditLimit { get; set; }
        public bool IsVIP { get; set; }
    }

    // Models with Bind attribute for safe binding
    public class SafeUserModel
    {
        [System.Web.Mvc.Bind(Include = "Username,Email")]
        public class UserDTO
        {
            public int Id { get; set; }
            public string Username { get; set; }
            public string Email { get; set; }
            public bool IsAdmin { get; set; }
        }
    }

    // Controller with vulnerable and safe methods
    public class VulnerableController : Controller
    {
// {fact rule=mass-assignment@v1.0 defects=1}
        // VULNERABLE EXAMPLES (TRUE POSITIVES)

        // Example 1: Basic mass assignment vulnerability with User model
        [HttpPost]
        public ActionResult bad_case_1(FormCollection form)
        {
            // ruleid: mass-assignment-csharp-rule
            User user = new User();
            UpdateModel(user); // Binds all properties from form data to user object
            
            SaveUser(user);
            return View(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 2: Mass assignment with TryUpdateModel
        [HttpPost]
        public ActionResult bad_case_2()
        {
            User user = new User();
            // ruleid: mass-assignment-csharp-rule
            TryUpdateModel(user); // Binds all properties from form data
            
            SaveUser(user);
            return View(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 3: Mass assignment with Product model
        [HttpPost]
        public ActionResult bad_case_3([FromBody] Product product)
        {
            // ruleid: mass-assignment-csharp-rule
            // Automatic model binding happens with [FromBody] attribute
            // An attacker could modify CostPrice or IsDiscontinued
            
            SaveProduct(product);
            return Ok(product);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 4: Mass assignment with Order model
        [HttpPost]
        public ActionResult bad_case_4()
        {
            Order order = new Order();
            // ruleid: mass-assignment-csharp-rule
            UpdateModel(order, new string[] { }); // Empty include list means bind everything
            
            SaveOrder(order);
            return View(order);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 5: Mass assignment with Employee model
        [HttpPost]
        public ActionResult bad_case_5([FromForm] Employee employee)
        {
            // ruleid: mass-assignment-csharp-rule
            // Automatic model binding happens with [FromForm] attribute
            // An attacker could modify Salary or IsManager
            
            SaveEmployee(employee);
            return Ok(employee);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 6: Mass assignment with Customer model using TryUpdateModel and prefix
        [HttpPost]
        public ActionResult bad_case_6()
        {
            Customer customer = new Customer();
            // ruleid: mass-assignment-csharp-rule
            TryUpdateModel(customer, "customerPrefix"); // Uses prefix but still binds all properties
            
            SaveCustomer(customer);
            return View(customer);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 7: Mass assignment with complex binding
        [HttpPost]
        public ActionResult bad_case_7()
        {
            User user = new User();
            // ruleid: mass-assignment-csharp-rule
            TryUpdateModel(user, new string[] { }, new string[] { "Password" }); // Excludes only password, but still vulnerable
            
            SaveUser(user);
            return View(user);
        }
// {/fact}

        // Example 8: Mass assignment in ASP.NET Core with [BindProperties]
        [Microsoft.AspNetCore.Mvc.BindProperties]
        public class bad_case_8 : Microsoft.AspNetCore.Mvc.Controller
        {
            // Properties will be automatically bound from request
            public User UserData { get; set; }

            [HttpPost]
            public IActionResult ProcessUser()
            {
                // ruleid: mass-assignment-csharp-rule
                // UserData is automatically bound from the request
                SaveUser(UserData);
                return Ok(UserData);
            }
        }
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 9: Mass assignment with dynamic type
        [HttpPost]
        public ActionResult bad_case_9()
        {
            dynamic model = new System.Dynamic.ExpandoObject();
            // ruleid: mass-assignment-csharp-rule
            TryUpdateModel(model); // Binds all properties to dynamic object
            
            SaveDynamicModel(model);
            return View(model);
        }
// {/fact}

        // Example 10: Mass assignment with nested objects
        public class UserWithRoles
        {
            public User User { get; set; }
            public List<string> Roles { get; set; }
        }
// {fact rule=mass-assignment@v1.0 defects=1}

        [HttpPost]
        public ActionResult bad_case_10([FromBody] UserWithRoles userWithRoles)
        {
            // ruleid: mass-assignment-csharp-rule
            // Automatic binding of nested objects can lead to mass assignment
            
            SaveUserWithRoles(userWithRoles);
            return Ok(userWithRoles);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 11: Mass assignment with dictionary
        [HttpPost]
        public ActionResult bad_case_11([FromBody] Dictionary<string, object> userProperties)
        {
            User user = new User();
            
            // ruleid: mass-assignment-csharp-rule
            foreach (var prop in userProperties)
            {
                typeof(User).GetProperty(prop.Key)?.SetValue(user, prop.Value);
            }
            
            SaveUser(user);
            return Ok(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 12: Mass assignment with reflection
        [HttpPost]
        public ActionResult bad_case_12(FormCollection form)
        {
            User user = new User();
            
            // ruleid: mass-assignment-csharp-rule
            foreach (var key in form.AllKeys)
            {
                var prop = typeof(User).GetProperty(key);
                if (prop != null)
                {
                    prop.SetValue(user, Convert.ChangeType(form[key], prop.PropertyType));
                }
            }
            
            SaveUser(user);
            return View(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 13: Mass assignment with JSON deserialization
        [HttpPost]
        public ActionResult bad_case_13()
        {
            var requestBody = new System.IO.StreamReader(Request.Body).ReadToEndAsync().Result;
            
            // ruleid: mass-assignment-csharp-rule
            User user = Newtonsoft.Json.JsonConvert.DeserializeObject<User>(requestBody);
            
            SaveUser(user);
            return Ok(user);
        }
// {/fact}

        // Example 14: Mass assignment with custom model binder
        public class CustomModelBinder : IModelBinder
        {
            public object BindModel(ControllerContext controllerContext, ModelBindingContext bindingContext)
            {
                var request = controllerContext.HttpContext.Request;
                var user = new User();
                
                // ruleid: mass-assignment-csharp-rule
                user.Id = int.Parse(request.Form["Id"]);
                user.Username = request.Form["Username"];
                user.Password = request.Form["Password"];
                user.IsAdmin = bool.Parse(request.Form["IsAdmin"]);
                user.AccountBalance = decimal.Parse(request.Form["AccountBalance"]);
                
                return user;
            }
        }
// {fact rule=mass-assignment@v1.0 defects=1}

        // Example 15: Mass assignment with AutoMapper
        [HttpPost]
        public ActionResult bad_case_15([FromBody] Dictionary<string, object> userDto)
        {
            // ruleid: mass-assignment-csharp-rule
            // AutoMapper configuration that maps all properties without restrictions
            var config = new AutoMapper.MapperConfiguration(cfg => 
                cfg.CreateMap<Dictionary<string, object>, User>());
            
            var mapper = config.CreateMapper();
            User user = mapper.Map<User>(userDto);
            
            SaveUser(user);
            return Ok(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

        // SAFE EXAMPLES (TRUE NEGATIVES)

        // Example 1: Safe binding with explicit Bind attribute
        [HttpPost]
        public ActionResult good_case_1([Microsoft.AspNetCore.Mvc.Bind("Username,Password")] User user)
        {
            // ok: mass-assignment-csharp-rule
            // Only Username and Password will be bound, IsAdmin and AccountBalance are protected
            
            SaveUser(user);
            return View(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

        // Example 2: Safe binding with Include parameter
        [HttpPost]
        public ActionResult good_case_2()
        {
            User user = new User();
            
            // ok: mass-assignment-csharp-rule
            UpdateModel(user, new string[] { "Username", "Password" }); // Only binds specified properties
            
            SaveUser(user);
            return View(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

        // Example 3: Safe binding with TryUpdateModel and Include
        [HttpPost]
        public ActionResult good_case_3()
        {
            User user = new User();
            
            // ok: mass-assignment-csharp-rule
            TryUpdateModel(user, new string[] { "Username", "Password" }); // Only binds specified properties
            
            SaveUser(user);
            return View(user);
        }
// {/fact}

        // Example 4: Safe binding with ViewModel pattern
        public class UserViewModel
        {
            public string Username { get; set; }
            public string Password { get; set; }
            // No sensitive properties like IsAdmin or AccountBalance
        }
// {fact rule=mass-assignment@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_4([FromBody] UserViewModel viewModel)
        {
            // ok: mass-assignment-csharp-rule
            // Using a view model that only contains safe properties
            User user = new User
            {
                Username = viewModel.Username,
                Password = viewModel.Password
                // IsAdmin and AccountBalance are not set from input
            };
            
            SaveUser(user);
            return View(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

        // Example 5: Safe binding with explicit property assignment
        [HttpPost]
        public ActionResult good_case_5(FormCollection form)
        {
            User user = new User();
            
            // ok: mass-assignment-csharp-rule
            // Explicitly assign only safe properties
            user.Username = form["Username"];
            user.Password = form["Password"];
            // IsAdmin and AccountBalance are not set from input
            
            SaveUser(user);
            return View(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

        // Example 6: Safe binding with [Bind] attribute on model
        [HttpPost]
        public ActionResult good_case_6([System.Web.Mvc.Bind(Include = "Name,Price")] Product product)
        {
            // ok: mass-assignment-csharp-rule
            // Only Name and Price will be bound, CostPrice and IsDiscontinued are protected
            
            SaveProduct(product);
            return View(product);
        }
// {/fact}

        // Example 7: Safe binding with DTO and manual mapping
        public class OrderDTO
        {
            public int Id { get; set; }
            public int UserId { get; set; }
            public decimal TotalAmount { get; set; }
            // No IsApproved or Discount properties
        }
// {fact rule=mass-assignment@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_7([FromBody] OrderDTO orderDTO)
        {
            // ok: mass-assignment-csharp-rule
            // Manual mapping from DTO to domain model
            Order order = new Order
            {
                Id = orderDTO.Id,
                UserId = orderDTO.UserId,
                TotalAmount = orderDTO.TotalAmount
                // IsApproved and Discount are not set from input
            };
            
            SaveOrder(order);
            return View(order);
        }
// {/fact}

        // Example 8: Safe binding with ReadOnlyAttribute
        public class SafeEmployee
        {
            public int Id { get; set; }
            public string Name { get; set; }
            public string Position { get; set; }
            
            [System.ComponentModel.ReadOnly(true)]
            public decimal Salary { get; set; }
            
            [System.ComponentModel.ReadOnly(true)]
            public bool IsManager { get; set; }
        }
// {fact rule=mass-assignment@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_8([FromBody] SafeEmployee employee)
        {
            // ok: mass-assignment-csharp-rule
            // ReadOnly attributes prevent binding to sensitive properties
            
            SaveSafeEmployee(employee);
            return Ok(employee);
        }
// {/fact}

        // Example 9: Safe binding with [BindNever] attribute
        public class SafeCustomer
        {
            public int Id { get; set; }
            public string Name { get; set; }
            public string Email { get; set; }
            
            [Microsoft.AspNetCore.Mvc.BindNever]
            public decimal CreditLimit { get; set; }
            
            [Microsoft.AspNetCore.Mvc.BindNever]
            public bool IsVIP { get; set; }
        }
// {fact rule=mass-assignment@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_9([FromBody] SafeCustomer customer)
        {
            // ok: mass-assignment-csharp-rule
            // BindNever attributes prevent binding to sensitive properties
            
            SaveSafeCustomer(customer);
            return Ok(customer);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

        // Example 10: Safe binding with explicit validation
        [HttpPost]
        public ActionResult good_case_10([FromBody] User user)
        {
            // ok: mass-assignment-csharp-rule
            // Explicitly validate and reset sensitive properties
            if (user.IsAdmin)
            {
                user.IsAdmin = false; // Override any attempt to set admin status
            }
            
            if (user.AccountBalance > 0)
            {
                user.AccountBalance = 0; // Override any attempt to set account balance
            }
            
            SaveUser(user);
            return Ok(user);
        }
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

        // Example 11: Safe binding with authorization check
        [HttpPost]
        [Authorize(Roles = "Administrator")]
        public ActionResult good_case_11([FromBody] User user)
        {
            // ok: mass-assignment-csharp-rule
            // Only administrators can access this endpoint, so binding all properties is acceptable
            // This is safe because we've restricted who can access the endpoint
            
            SaveUser(user);
            return Ok(user);
        }
// {/fact}

        // Example 12: Safe binding with custom model binder that filters properties
        public class SafeUserModelBinder : IModelBinder
        {
            public object BindModel(ControllerContext controllerContext, ModelBindingContext bindingContext)
            {
                var request = controllerContext.HttpContext.Request;
                var user = new User();
                
                // ok: mass-assignment-csharp-rule
                // Only bind safe properties
                user.Username = request.Form["Username"];
                user.Password = request.Form["Password"];
                // Explicitly do not bind IsAdmin or AccountBalance
                
                return user;
            }
        }
// {fact rule=mass-assignment@v1.0 defects=0}

        // Example 13: Safe binding with AutoMapper and explicit configuration
        [HttpPost]
        public ActionResult good_case_13([FromBody] Dictionary<string, object> userDto)
        {
            // ok: mass-assignment-csharp-rule
            // AutoMapper configuration that explicitly maps only safe properties
            var config = new AutoMapper.MapperConfiguration(cfg => {
                cfg.CreateMap<Dictionary<string, object>, User>()
                   .ForMember(dest => dest.IsAdmin, opt => opt.Ignore())
                   .ForMember(dest => dest.AccountBalance, opt => opt.Ignore());
            });
            
            var mapper = config.CreateMapper();
            User user = mapper.Map<User>(userDto);
            
            SaveUser(user);
            return Ok(user);
        }
// {/fact}

        // Example 14: Safe binding with JSON deserialization and JsonProperty attributes
        public class SafeJsonUser
        {
            public int Id { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            
            [Newtonsoft.Json.JsonIgnore]
            public bool IsAdmin { get; set; }
            
            [Newtonsoft.Json.JsonIgnore]
            public decimal AccountBalance { get; set; }
        }
// {fact rule=mass-assignment@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_14()
        {
            var requestBody = new System.IO.StreamReader(Request.Body).ReadToEndAsync().Result;
            
            // ok: mass-assignment-csharp-rule
            // JsonIgnore attributes prevent binding to sensitive properties
            SafeJsonUser user = Newtonsoft.Json.JsonConvert.DeserializeObject<SafeJsonUser>(requestBody);
            
            SaveSafeJsonUser(user);
            return Ok(user);
        }
// {/fact}

        // Example 15: Safe binding with [ModelBinder] attribute
        public class SafeModelBinder : IModelBinder
        {
            public object BindModel(ControllerContext controllerContext, ModelBindingContext bindingContext)
            {
                // Only bind safe properties
                return new User
                {
                    Username = bindingContext.ValueProvider.GetValue("Username")?.AttemptedValue,
                    Password = bindingContext.ValueProvider.GetValue("Password")?.AttemptedValue
                    // IsAdmin and AccountBalance are not bound
                };
            }
        }
// {fact rule=mass-assignment@v1.0 defects=0}

        [HttpPost]
        public ActionResult good_case_15([ModelBinder(typeof(SafeModelBinder))] User user)
        {
            // ok: mass-assignment-csharp-rule
            // Custom model binder that only binds safe properties
            
            SaveUser(user);
            return Ok(user);
        }
// {/fact}

        // Helper methods to make the examples complete
        private void SaveUser(User user) { /* Save user to database */ }
        private void SaveProduct(Product product) { /* Save product to database */ }
        private void SaveOrder(Order order) { /* Save order to database */ }
        private void SaveEmployee(Employee employee) { /* Save employee to database */ }
        private void SaveCustomer(Customer customer) { /* Save customer to database */ }
        private void SaveDynamicModel(dynamic model) { /* Save dynamic model to database */ }
        private void SaveUserWithRoles(UserWithRoles userWithRoles) { /* Save user with roles to database */ }
        private void SaveSafeEmployee(SafeEmployee employee) { /* Save safe employee to database */ }
        private void SaveSafeCustomer(SafeCustomer customer) { /* Save safe customer to database */ }
        private void SaveSafeJsonUser(SafeJsonUser user) { /* Save safe JSON user to database */ }
    }
}