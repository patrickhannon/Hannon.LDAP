using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Hannon.Ldap.Models;
using Newtonsoft.Json;
using System.Diagnostics;

namespace Hannon.Ldap
{
    class Program
    {
        private static string _lDAPUser;
        private static string _lDAPPath;
        private static string _lDAPPassword;
        private static string _lDAPDomain;

        static void Main(string[] args)
        {
            _lDAPUser = ConfigurationManager.AppSettings["LDAPUser"];
            _lDAPDomain = ConfigurationManager.AppSettings["LDAPPath"];
            _lDAPPassword = ConfigurationManager.AppSettings["LDAPPassword"];
            _lDAPPath = ConfigurationManager.AppSettings["LDAPDomain"];

            //if (args.Length != 4)
            //{
            //    Debug.WriteLine("Usage: LDAPClient <username> <domain> <password> <LDAP server URL>");
            //    Environment.Exit(1);
            //}
            //var client = new LdapHelper(args[0], args[1], args[2], args[3]);

            var client = new LdapHelper(_lDAPUser, _lDAPDomain, _lDAPPassword, _lDAPPath);

            //Searching for all users
            var searchResult = client.search("cn=Users,dc=hannon,dc=local", "objectClass=*");
            foreach (Dictionary<string, string> d in searchResult)
            {
                Debug.WriteLine(String.Join("\r\n", d.Select(x => x.Key + ": " + x.Value).ToArray()));
            }

            //Validating credentials using LDAP bind
            //For this to work the server must be configured to map users correctly to its internal database
            if (client.ValidateUserByBind(_lDAPUser, _lDAPPassword))
            {
                Debug.WriteLine("Valid credentials (bind)");
            }
            else
            {
                Debug.WriteLine("Invalid credentials (bind)");
            }

            try
            {
                //Adding a user
                client.AddUser(new UserModel("cn=sampleuser,cn=users,dc=hannon,dc=local",
                    "sampleuser", "Users", "plaintextpass"));
            }
            catch (Exception e)
            {
                //The user may already exist
                Debug.WriteLine(e);
            }

        }
    }
}
