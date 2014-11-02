using System;
using System.Diagnostics;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Text;

namespace SymEnc.Core
{
    public class SymmetricEncyrptionSvc
    {
        /* 
         * CHANGE THIS KEY FOR YOUR APPLICATION!!
         * Generate your key using the console application located with the source code at https://github.com/Hallmanac/SymEnc.
         * This key is used for encrypting/decrypting site data and is used as the default key when no key is given.
         * For use cases that require interaction outside of the site, we would generate a new random (private) key for each instance where
         * we would store the generated key as well as the client app would store the generated private key.
        */
        public const string Default256BitKey = "16CF22659BB1DE3038B2058C98687A21ED9F103A1162BC32E35BCCC46A905C5B";

        /// <summary>
        /// Creates a RijndaelManaged cipher based on the given key material with a default 256 block size. If no key is given then the 
        /// <see cref="Default256BitKey"/> is used.
        /// </summary>
        public RijndaelManaged CreateCipher(string key = "", int blockSize = 256)
        {
            if(((blockSize % 256) != 0) || ((blockSize % 256) != 128))
                blockSize = 256;
            if(string.IsNullOrEmpty(key))
                key = Default256BitKey;
            byte[] byteKey;
            try
            {
                byteKey = HexToByteArray(key);
                if(byteKey.Length != 32)
                    byteKey = HexToByteArray(Default256BitKey);
            }
            catch(Exception)
            {
                byteKey = HexToByteArray(Default256BitKey);
            }
            var cipher = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = blockSize,
                Padding = PaddingMode.ISO10126,
                Mode = CipherMode.CBC,
                Key = byteKey
            };
            return cipher;
        }

        /// <summary>
        /// Encrypts a string using the given key. To Decrypt you will need the proper initialization vector that gets randomly generated
        /// for each encryption process (i.e. different every time the encryption is run). This will happen automatically in our Decrypt 
        /// method on this class because we're prefixing those initialization vectors with the encrypted text.
        /// </summary>
        /// <param name="plainText">Text value to be encrypted</param>
        /// <param name="key">MUST be a hex string based on a 256 bit byte array (i.e. new byte[32])</param>
        /// <param name="blockSize">Size of block used in the Rijndael algorithm</param>
        /// <returns>Encrypted Hexadecimal string of the given <see cref="plainText"/></returns>
        public string Encrypt(string plainText, string key = "", int blockSize = 256)
        {
            if(string.IsNullOrEmpty(key))
                key = Default256BitKey;
            var cipher = CreateCipher(key, blockSize);
            var initVector = BytesToHexString(cipher.IV);

            // Create the encryptor, convert to bytes, and encrypt the plainText string
            var cryptoTransform = cipher.CreateEncryptor();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherTextBytes = cryptoTransform.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);

            // Get the Hexadecimal string of the cipherTextBytes, hash it, and prefix the Initialization Vector to it.
            // We're using a hexadecimal string so that the cipherText can be used in URL's. Yes, there are other ways of doing that, but it's a style
            // choice.
            var cipherText = BytesToHexString(cipherTextBytes);
            return initVector + "_" + cipherText;
        }

        /// <summary>
        /// Decrypts a given cipher text based on the provided key material. The initialization vector should be prefixed to the cipher text followed
        /// by an underscore for delimiting.
        /// </summary>
        /// <param name="cipherText">Text to be decrypted</param>
        /// <param name="key">MUST be a hex string based on a 256 bit byte array (i.e. new byte[32])</param>
        /// <param name="blockSize">Size of block used in the Rijndael algorithm</param>
        /// <returns></returns>
        public string Decrypt(string cipherText, string key = "", int blockSize = 256)
        {
            try
            {
                if (string.IsNullOrEmpty(key))
                    key = Default256BitKey;
                var cipher = CreateCipher(key, blockSize);
                var splitCipherText = cipherText.Split('_');
                if (splitCipherText.Length != 2)
                    return null;
                var initVector = splitCipherText[0];
                var encString = splitCipherText[1];
                if (0 != initVector.Length % 2 || 0 != encString.Length % 2)
                    return null;

                cipher.IV = HexToByteArray(initVector);
                var cryptoTransform = cipher.CreateDecryptor();
                var cipherBytes = HexToByteArray(encString);
                if (cipherBytes == null)
                    return null;
                var plainTextBytes = cryptoTransform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                return Encoding.UTF8.GetString(plainTextBytes);
            }
            catch (Exception e)
            {
                Trace.WriteLine(e.Message);
                return string.Empty;
            }
        }

        /// <summary>
        /// Checks to see if the given text is encrypted based on the logic in this class.
        /// </summary>
        public bool IsEncrypted(string text)
        {
            var decrypted = Decrypt(text);
            return !string.IsNullOrEmpty(decrypted);
        }

        /// <summary>
        /// Generates random, non-zero bytes using the RNGCryptoServiceProvider
        /// </summary>
        /// <param name="buffer">Length of random bytes to be generated.</param>
        public void GenerateRandomBytes(byte[] buffer)
        {
            var rng = new RNGCryptoServiceProvider();
            rng.GetNonZeroBytes(buffer);
        }

        /// <summary>
        /// Generates a random byte array key based on the byte length given and returns it as a hexadecimal string.
        /// </summary>
        /// <param name="byteLength">Length of Byte array used in the random generator</param>
        /// <returns>Hexadecimal text representation of the randomly generated bytes.</returns>
        public string GenerateKeyFromByteLength(int byteLength)
        {
            var key = new byte[byteLength];
            GenerateRandomBytes(key);
            return BytesToHexString(key);
        }

        /// <summary>
        /// Generates a random 256 bit key (in a byte array) and returns it as a hexadecimal string.
        /// </summary>
        /// <returns>A hexadecimal string based on the randomly generated 256 bit key byte array</returns>
        public string Generate256BitKey()
        {
            var key = new byte[32];
            GenerateRandomBytes(key);
            return BytesToHexString(key);
        }

        /// <summary>
        /// This will compute a basic SHA1 hash for uses within this Encryption Service class. This hash is not recommended for
        /// true security use cases. For great security checkout PWDTK.Net https://github.com/Thashiznets/PWDTK.NET?source=c
        /// </summary>
        public string ComputeBasicHash(string textToHash, string salt = "")
        {
            var hashAlgorithm = new SHA1Managed();
            var hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(textToHash + salt));
            var hashHexString = BytesToHexString(hash);
            return hashHexString;
        }

        /// <summary>
        /// Converts a given byte array into a hexadecimal string.
        /// </summary>
        public string BytesToHexString(byte[] byteArray) { return new SoapHexBinary(byteArray).ToString(); }

        /// <summary>
        /// Converts a given hexadecimal string into a byte array. The Hex string must be in multiple of 2's in length or it will throw an exception.
        /// </summary>
        public byte[] HexToByteArray(string hexString)
        {
            if(0 != (hexString.Length % 2))
                throw new ApplicationException("Hex string must be multiple of 2 in length");
            var byteCount = hexString.Length / 2;
            var byteValues = new byte[byteCount];
            for(var i = 0; i < byteCount; i++)
            {
                byteValues[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return byteValues;
        }

        /// <summary>
        /// Computes a hash based on the HMACSHA1 algorithm using the given key.
        /// </summary>
        public string ComputeHmacSha1ForHex(string textToHash, string key = Default256BitKey)
        {
            var hmacSha1 = new HMACSHA1(Encoding.UTF8.GetBytes(key));
            var hash = hmacSha1.ComputeHash(Encoding.UTF8.GetBytes(textToHash));
            var hashToHexString = new SoapHexBinary(hash).ToString();
            return hashToHexString;
        }

        /// <summary>
        /// Computes a hash based on the HMACSHA1 algorithm using the given key and returns a Base64 encoded string.
        /// </summary>
        public string ComputeHmacSha1ForBase64(string textToEncode, string key = Default256BitKey)
        {
            var hmacSha1 = new HMACSHA1(Encoding.UTF8.GetBytes(key));
            var hash = hmacSha1.ComputeHash(Encoding.UTF8.GetBytes(textToEncode));
            var base64String = Convert.ToBase64String(hash);
            return base64String;
        }
    }
}