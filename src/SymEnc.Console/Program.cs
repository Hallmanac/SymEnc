using System;
using System.CodeDom;

using SymEnc.Core;

namespace SymEnc.ConsoleApp
{
	internal class Program
	{
		private const string Key = "177FCB81EABEECB05431D165955A2979D8E726F1B3160774106D5417775E36C1";

		private static void Main(string[] args)
		{
			var symEnc = new SymmetricEncyrptionSvc(Key);
			var continueGenerating256BitKeys = true;
			while(continueGenerating256BitKeys)
			{
				var keyFor256 = symEnc.Generate256BitKey();
				Console.WriteLine("The generated 256 bit key is:\n{0}", keyFor256);
				Console.WriteLine("\nWould you like to generate another 256 bit key? (Y or N)");
				var continueAnswer = Console.ReadLine();
				continueGenerating256BitKeys = !string.IsNullOrEmpty(continueAnswer) &&
				                               (string.Equals("Y", continueAnswer, StringComparison.CurrentCultureIgnoreCase) ||
				                                string.Equals("yes", continueAnswer, StringComparison.CurrentCultureIgnoreCase));
			}
			Console.WriteLine("\nEnter an even numbered integer to generate a hexidecimal key based on that length...");
			var keySizeStr = Console.ReadLine();
			int keySize;
			if(Int32.TryParse(keySizeStr, out keySize))
			{
				// Hex key
				var generatedKey = symEnc.GenerateHexKeyFromByteLength(keySize);
				Console.WriteLine("\nThe generated key based on a length of {0} is:\n{1}", keySizeStr, generatedKey);

				// Base64 key
				var base64Key = symEnc.GenerateBase64KeyFromByteLength(keySize);
				Console.WriteLine("\nThe generated Base64 key based on a length of {0} is:\n{1}", keySizeStr, base64Key);

				// 64 bit number
				var random64BitNumber = symEnc.GenerateRandom64BitNumberFromByteLength(keySize);
				Console.WriteLine("\nThe generated 64 bit random number based on a length of {0} is:\n{1}", keySizeStr, random64BitNumber);

				// 32 bit number
				var random32BitNumber = symEnc.GenerateRandom32BitNumberFromByteLength(keySize);
				Console.WriteLine("\nThe generated 32 bit random number based on a length of {0} is:\n{1}", keySizeStr, random32BitNumber);

			}
			else
				Console.WriteLine("\nThe value entered for a key was invalid.");
			Console.WriteLine("\nEnter a string to hash using the HMACSHA1 algorithm.");
			var textToHash = Console.ReadLine();
			var hashedText = symEnc.ComputeHmacSha1ForHex(textToHash);
			Console.WriteLine("\nThe computed hash is:\n{0}", hashedText);

		    var continueEncryption = true;
		    while (continueEncryption)
		    {
                Console.WriteLine("\nEnter a 256bit key for custom encryption:");
                var customKey = Console.ReadLine();
                Console.WriteLine("\nEnter value to encrypt:");
                var valueToEncrypt = Console.ReadLine();
                var encryptedText = symEnc.Encrypt(valueToEncrypt, customKey);
                Console.WriteLine($"The encrypted text is:\n{encryptedText}");
		        Console.WriteLine("\nWould you like to encrypt another value? (Y or N)");
		        var answer = Console.ReadLine();
                continueEncryption = !string.IsNullOrEmpty(answer) &&
                                               (string.Equals("Y", answer, StringComparison.CurrentCultureIgnoreCase) ||
                                                string.Equals("yes", answer, StringComparison.CurrentCultureIgnoreCase));
            }
			Console.ReadKey();
		}
	}
}