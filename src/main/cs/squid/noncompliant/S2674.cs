using System;
using System.IO;

namespace SonarqubeCsharp.GeneralTestCodes
{
    public class S2674_noncompliant
    {
        public void DoSomething(string fileName)
        {
            using (var stream = File.Open(fileName, FileMode.Open))
            {
                var result = new byte[stream.Length];
                stream.Read(result, 0, (int)stream.Length); // Noncompliant
                                                            // ... do something with result
            }
        }
    }
}