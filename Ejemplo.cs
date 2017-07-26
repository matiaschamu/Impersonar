using System;
using System.Threading;
using System.Security;
using System.Security.Principal;
using System.IO;
using Xealcom.Security;

//Este es un ejemplo de uso para la clase Impersonator y no debe ser compilado
namespace Impersonator
{
   class Program
   {
      static void Main() {
         SingleThreadImpersonation();

         MultipleThreadImpersonation();
      }

      // Shows impersonation on a single thread
      private static void SingleThreadImpersonation() {
         try {
            // Show current user identity
            CheckIdentity();
            // Try accessing a file where current user has "Access Denied" permissions
            // will get "Access Denied" error
            TestFileOps();

            // Impersonate user
            ImpersonateUser iU = new ImpersonateUser();
            // TODO: Replace credentials
            iU.Impersonate("remoteMachine", "userID", "password");
            // Show new user identity
            CheckIdentity();
            // Try accessing the file: should have no problems
            TestFileOps();

            // Revert back to the previous user identity
            iU.Undo();
            CheckIdentity();

            // Try accessing the same file - error "access denied"
            TestFileOps();
         }
         catch (Exception e) {
            Console.WriteLine(e.Message);
         }
      }


      // Impersonates different user on multiple threads
      // TODO: In ThreadStart(CheckIdentity) replace CheckIdentity with 
      //       TestFileOps method to see how access to file changes
      private static void MultipleThreadImpersonation() {
         try {
            // This thread will run in security context of Main()
            Thread t0 = new Thread(new ThreadStart(CheckIdentity));
            t0.Start();
            t0.Join();

            // Impersonate
            ImpersonateUser iU = new ImpersonateUser();
            // TODO: Replace credentials
            iU.Impersonate("remoteMachine", "userID", "password");

            // This thread will run in security context of the impersonated user
            Thread t1 = new Thread(new ThreadStart(CheckIdentity));
            t1.Start();
            t1.Join();

            // Supress the flow of Windows identity between threads
            AsyncFlowControl aFC2 = SecurityContext.SuppressFlowWindowsIdentity();

            // This thread will run in sec context of the Main() thread
            Thread t2 = new Thread(new ThreadStart(CheckIdentity));
            t2.Start();
            t2.Join();


            // Restore the flow of the Windows identity for the impersonated user
            // between threads
            aFC2.Undo();

            // This thread will run in the security context of
            // IMPERSONATED(second) user
            Thread t3 = new Thread(new ThreadStart(CheckIdentity));
            t3.Start();
            t3.Join();

            // Stop impersonation
            iU.Undo();
         }
         catch (Exception e) {
            Console.WriteLine(e.Message);
         }
      }


      // Displays identity of the current thread
      static void CheckIdentity() {
         Console.WriteLine("Current user: " + WindowsIdentity.GetCurrent().Name);
      }



      // Simulates some real work that you need to be done
      static void TestFileOps() {
         try {
            // TODO: Replace file path
            using (StreamReader sr = new StreamReader(@"\\remoteMachine\c$\test.txt")) {
               string line;

               while ((line = sr.ReadLine()) != null) {
                  Console.WriteLine("Read line form file: {0}", line);
               }
            }
         }
         catch (Exception ex) {
            Console.WriteLine("Error: {0}", ex.Message);
         }
      }
   }
}
