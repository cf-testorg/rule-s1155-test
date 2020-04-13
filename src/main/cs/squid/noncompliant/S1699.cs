using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SonarqubeCsharp.GeneralTestCodes
{
    public class S1699
    {
        public S1699()
        {
            DoSomething();
        }

        public virtual void DoSomething() // can be overridden
        {
            var a = 5;
        }
    }
}