using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography;
using Hannon.Ldap.Models;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace Hannon.Ldap
{
    public class LdapHelper
    {
        private LdapConnection _connection;
        public LdapHelper(string username, string domain, string password, string url)
        {
            var credentials = new NetworkCredential(username, password, domain);
            var serverId = new LdapDirectoryIdentifier(url);

            _connection = new LdapConnection(serverId, credentials);

        }
        public bool ValidateUserByBind(string username, string password)
        {
            bool result = true;
            var credentials = new NetworkCredential(username, password);
            var serverId = new LdapDirectoryIdentifier(_connection.SessionOptions.HostName);

            var conn = new LdapConnection(serverId, credentials);
            try
            {
                conn.Bind();
            }
            catch (Exception)
            {
                result = false;
            }
            conn.Dispose();
            return result;
        }
        public bool ValidateUser(string username, string password)
        {
            var sha1 = new SHA1Managed();
            var digest = Convert.ToBase64String(sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)));
            var request = new CompareRequest(string.Format("uid={0},ou=users,dc=example,dc=com", username),
                "userPassword", "{SHA}" + digest);
            var response = (CompareResponse)_connection.SendRequest(request);
            return response.ResultCode == ResultCode.CompareTrue;
        }
        public void AddUser(UserModel user)
        {
            DirectoryEntry ouEntry = new DirectoryEntry("LDAP://CN=Users,DC=Hannon,DC=local");
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    DirectoryEntry childEntry = ouEntry.Children.Add("CN=TestUser" + i, "user");
                    childEntry.CommitChanges();
                    ouEntry.CommitChanges();
                    childEntry.Invoke("SetPassword", new object[] { "Password123" });
                    childEntry.CommitChanges();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(ex);
                }
            }
        }

        public List<Dictionary<string, string>> search(string baseDn, string ldapFilter)
        {
            var request = new SearchRequest(baseDn, ldapFilter, SearchScope.Subtree, null);
            var response = (SearchResponse)_connection.SendRequest(request);

            var result = new List<Dictionary<string, string>>();

            foreach (SearchResultEntry entry in response.Entries)
            {
                var dic = new Dictionary<string, string>();
                dic["DN"] = entry.DistinguishedName;

                foreach (string attrName in entry.Attributes.AttributeNames)
                {
                    //For simplicity, we ignore multi-value attributes
                    dic[attrName] = string.Join(",", entry.Attributes[attrName].GetValues(typeof(string)));
                }

                result.Add(dic);
            }

            return result;
        }


    }
}
