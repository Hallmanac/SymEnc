using System;
using SymEnc.Core;

namespace SymEnc.Console
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var symEnc = new SymmetricEncyrptionSvc();
            var continueGenerating256BitKeys = true;
            while(continueGenerating256BitKeys)
            {
                var keyFor256 = symEnc.Generate256BitKey();
                System.Console.WriteLine("The generated 256 bit key is:\n{0}", keyFor256);
                System.Console.WriteLine("\nWould you like to generate another 256 bit key? (Y or N)");
                var continueAnswer = System.Console.ReadLine();
                continueGenerating256BitKeys = !string.IsNullOrEmpty(continueAnswer) &&
                                               (string.Equals("Y", continueAnswer, StringComparison.CurrentCultureIgnoreCase) ||
                                                string.Equals("yes", continueAnswer, StringComparison.CurrentCultureIgnoreCase));
            }
            
            System.Console.WriteLine("\nEnter an even numbered integer to generate a hexidecimal key based on that length...");

            var keySizeStr = System.Console.ReadLine();
            int keySize;
            if(Int32.TryParse(keySizeStr, out keySize))
            {
                var generatedKey = symEnc.GenerateKeyFromByteLength(keySize);
                System.Console.WriteLine("\nThe generated key based on a length of {0} is:\n{1}", keySizeStr, generatedKey);
            }
            else
            {
                System.Console.WriteLine("\nThe value entered for a key was invalid.");
            }
            System.Console.WriteLine("\nEnter a string to hash using the HMACSHA1 algorithm.");
            var textToHash = System.Console.ReadLine();
            var hashedText = symEnc.ComputeHmacSha1ForHex(textToHash);

            System.Console.WriteLine("\nThe computed hash is:\n{0}", hashedText);
        }
    }
}