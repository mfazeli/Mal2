//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Generic;
using StuffNeededForWork.Commands;

namespace StuffNeededForWork
{
    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();


        public CommandCollection()
        {
            _availableCommands.Add(CAs.CommandName, () => new CAs());
            _availableCommands.Add(Request.CommandName, () => new Request());
            _availableCommands.Add(Download.CommandName, () => new Download());
            _availableCommands.Add(Find.CommandName, () => new Find());
            _availableCommands.Add(PKIObjects.CommandName, () => new PKIObjects());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            bool commandWasFound;

            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound= false;
            else
            {
                var command = _availableCommands[commandName].Invoke();
                
                command.Execute(arguments);

                commandWasFound = true;
            }

            return commandWasFound;
        }
    }
}