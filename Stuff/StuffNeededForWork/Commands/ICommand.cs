//start
using System.Text;
using System.Linq;
using System;
﻿using System.Collections.Generic;

namespace StuffNeededForWork.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}