//start
using System.Text;
using System.Linq;
using System;
﻿using System.DirectoryServices;

namespace StuffNeededForWork.Domain
{
    public class ADObject
    {
        public string DistinguishedName { get; set; }
        public ActiveDirectorySecurity? SecurityDescriptor { get; set; }
        public ADObject(string distinguishedName, ActiveDirectorySecurity? securityDescriptor)
        {
            DistinguishedName = distinguishedName;
            SecurityDescriptor = securityDescriptor;    
        }
    }
}
