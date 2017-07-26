using System;
using System.ComponentModel;
using System.Threading;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.Runtime.InteropServices;


namespace BibliotecaMaf.Clases.Impersonar
{
   /// <summary>
   /// Performs user impersonation. 
   /// </summary>
   public class ImpersonateUser
   {
      [DllImport("advapi32.dll", SetLastError = true)]
      public static extern bool LogonUser(
          String lpszUsername,
          String lpszDomain,
          String lpszPassword,
          int dwLogonType,
          int dwLogonProvider,
          ref IntPtr phToken);

      [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
      private extern static bool CloseHandle(IntPtr handle);

      private static IntPtr tokenHandle = new IntPtr(0);
      private static WindowsImpersonationContext impersonatedUser;

      // If you incorporate this code into a DLL, be sure to demand that it
      // runs with FullTrust.
      [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
      public void Impersonate(string domainName, string userName, string password) {
         //try {

            // Use the unmanaged LogonUser function to get the user token for
            // the specified user, domain, and password.
            const int LOGON32_PROVIDER_DEFAULT = 0;

            // Passing this parameter causes LogonUser to create a primary token.
            const int LOGON32_LOGON_INTERACTIVE = 2;
            tokenHandle = IntPtr.Zero;
            
            // Step -1 Call LogonUser to obtain a handle to an access token.
            bool returnValue = LogonUser(
                userName,
                domainName,
                password,
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                ref tokenHandle);         // tokenHandle - new security token

            if (false == returnValue) {
               int ret = Marshal.GetLastWin32Error();
               Console.WriteLine("LogonUser call failed with error code : " +
                   ret);
               throw new Win32Exception(ret);
            }

            // Step - 2
            WindowsIdentity newId = new WindowsIdentity(tokenHandle);
            // Step -3
            impersonatedUser = newId.Impersonate();

         //}
         //catch (Exception ex) {
         //   Console.WriteLine("Exception occurred. " + ex.Message);
         //}
      }

      /// <summary>
      /// Stops impersonation
      /// </summary>
      public void Undo() {
         impersonatedUser.Undo();
         // Free the tokens.
         if (tokenHandle != IntPtr.Zero)
            CloseHandle(tokenHandle);
      }

	   public WindowsIdentity CheckCurrentUser
	   {
		   get
		   {
			   return WindowsIdentity.GetCurrent();
		   }
	   }



   }
}
