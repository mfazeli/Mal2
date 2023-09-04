//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using StuffNeededForWork.Domain;
using StuffNeededForWork.Lib;

namespace StuffNeededForWork.Commands
{
    public class PKIObjects : ICommand
    {
        public static string CommandName => new string("cxvbowrpgf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
        private LdapOperations _ldap = new LdapOperations();
        private bool hideAdmins;
        private string? domain;
        private string? ldapServer;

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine(new string("[*] Npgvba: Svaq CXV bowrpg pbagebyyref".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            hideAdmins = !arguments.ContainsKey(new string("/fubjNqzvaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            if (arguments.ContainsKey(new string("/qbznva".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                domain = arguments[new string("/qbznva".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
                if (!domain.Contains("."))
                {
                    Console.WriteLine(new string("[!] /qbznva:K zhfg or n SDQA".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    return;
                }
            }

            if (arguments.ContainsKey(new string("/yqncfreire".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                ldapServer = arguments[new string("/yqncfreire".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
            }

            _ldap = new LdapOperations(new LdapSearchOptions()
            {
                Domain = domain, LdapServer = ldapServer
            });

            Console.WriteLine($"[*] Using the search base '{_ldap.ConfigurationPath}'");

            DisplayPKIObjectControllers();
        }

        private void DisplayPKIObjectControllers()
        {
            Console.WriteLine(new string("\a[*] CXV Bowrpg Pbagebyyref:".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            var pkiObjects = _ldap.GetPKIObjects();
            
            DisplayUtil.PrintPKIObjectControllers(pkiObjects, hideAdmins);
        }
    }
}
