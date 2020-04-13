using System;
using System.IO;

namespace SonarqubeCsharp.GeneralTestCodes
{
    public class S2674_compliant
    {
      public void DoSomething(string fileName)
      {
        using (var stream = File.Open(fileName, FileMode.Open))
        {
          var buffer = new byte[1024];
          using (var ms = new MemoryStream())
          {
              int read;
              while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
              {
                  ms.Write(buffer, 0, read);
              }
              // ... do something with ms
          }
        }
      }
    }
}