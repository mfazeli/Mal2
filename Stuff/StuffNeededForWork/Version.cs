//start
using System.Text;
using System.Linq;
using System;
﻿namespace StuffNeededForWork
{
    public static class Version
    {
        public static string version = new string("1.1.0".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
    }
}
