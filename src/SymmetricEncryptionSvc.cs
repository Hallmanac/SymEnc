namespace SymEnc
{
    using System;
    using System.Runtime.Remoting.Metadata.W3cXsd2001;
    using System.Security.Cryptography;
    using System.Text;

    public class SymmetricEncyrptionSvc
    {
        /* 
         * CHANGE THIS KEY FOR YOUR APPLICATION!!
         * Generated randomly from http://www.random.org/bytes/ --> choose to generate 32 random bytes and output Hexadecimal string
         * This key is used for encrypting/decrypting site data and is used as the default key when no key is given.
         * For use cases that require interaction outside of the site, we would generate a new random (private) key for each instance where
         * we would store the generated key as well as the client app would store the generated private key.
        */
        public const string Default256BitKey = "ef2591793d9644c8bdd9f8eb31bf0ed2dd6b3a8358c6af07e9ad0b0e9147d311";

        private readonly ICipherCache _cipherCache;
        private readonly ICipherRepo _cipherRepo;

        public SymmetricEncyrptionSvc(ICipherRepo cipherRepo, ICipherCache cipherCache)
        {
            _cipherCache = cipherCache;
            _cipherRepo = cipherRepo;
        }

        public RijndaelManaged CreateCipher(string key = "", int blockSize = 256)
        {
            if (((blockSize % 256) != 0) || ((blockSize % 256) != 128))
            {
                blockSize = 256;
            }
            if (string.IsNullOrEmpty(key))
            {
                key = Default256BitKey;
            }
            byte[] byteKey;
            try
            {
                byteKey = HexToByteArray(key);
                if (byteKey.Length != 32)
                {
                    byteKey = HexToByteArray(Default256BitKey);
                }
            }
            catch (Exception)
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
        /// method on this class because we're storing those initialization vectors with the encrypted text, BUT if you want to allow someone
        /// else to be able to decrypt our cipher text then they'll need the private key as well as the initialization vector.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="initVector"></param>
        /// <param name="key">MUST be a hex string based on a 256 bit byte array (i.e. new byte[32])</param>
        /// <param name="blockSize"></param>
        /// <returns></returns>
        public string Encrypt(string plainText, string initVector = null, string key = "", int blockSize = 256)
        {
            if (string.IsNullOrEmpty(key))
            {
                key = Default256BitKey;
            }
            var cipher = CreateCipher(key, blockSize);
            if (initVector != null)
            {
                cipher.IV = HexToByteArray(initVector);
            }
            else
            {
                initVector = BytesToHexString(cipher.IV);
            }

            // Create the encryptor, convert to bytes, and encrypt the plainText string
            var cryptoTransform = cipher.CreateEncryptor();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherTextBytes = cryptoTransform.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);

            // Get the Hexadecimal string of the cipherTextBytes, hash it, and store it in the cache and the database with the Initialization Vector.
            // We're hashing it to save space on the storage mechanisms
            // We're using a hexadecimal string so that the cipherText can be used in URL's. Yes, there are other ways of doing that, but it's a style
            // choice.
            var cipherText = BytesToHexString(cipherTextBytes);
            var hashedCipherText = ComputeBasicHash(cipherText);
            _cipherRepo.SaveCipherTextAndVector(hashedCipherText, initVector);
            _cipherCache.SaveCipherTextAndVector(hashedCipherText, initVector);

            return cipherText;
        }

        /// <summary>
        /// Decrypts a given cipher text based on the provided key material. If the Initialization Vector is provided then that is what
        /// will be used in the decryption process. If not then we will search the cache and database for an instance of CipherValues that 
        /// has the same HashedCipherText value as the given cipherText parameter and use the value of that InitVector.
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="initVector"></param>
        /// <param name="key">MUST be a hex string based on a 256 bit byte array (i.e. new byte[32])</param>
        /// <param name="blockSize"></param>
        /// <returns></returns>
        public string Decrypt(string cipherText, string initVector = null, string key = "", int blockSize = 256)
        {
            if (string.IsNullOrEmpty(key))
            {
                key = Default256BitKey;
            }
            var cipher = CreateCipher(key, blockSize);
            if (initVector == null)
            {
                initVector = GetStoredInitVector(cipherText);
                if (initVector == null) return string.Empty;
            }
            cipher.IV = HexToByteArray(initVector);

            var cryptoTransform = cipher.CreateDecryptor();
            var cipherBytes = HexToByteArray(cipherText);
            var plainTextBytes = cryptoTransform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(plainTextBytes);
        }

        public void GenerateRandomBytes(byte[] buffer)
        {
            var rng = new RNGCryptoServiceProvider();
            rng.GetNonZeroBytes(buffer);
        }

        public string Generate256BitKey()
        {
            var key = new byte[32];
            GenerateRandomBytes(key);
            return BytesToHexString(key);
        }

        /// <summary>
        /// This will compute a basic SHA1 hash for uses within this Encryption Service class. This hash is not recommended for
        /// true security use cases. 
        /// </summary>
        /// <param name="textToHash"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public string ComputeBasicHash(string textToHash, string salt = "")
        {
            var hashAlgorithm = new SHA1Managed();
            var hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(textToHash + salt));
            var hashHexString = BytesToHexString(hash);
            return hashHexString;
        }

        public string BytesToHexString(byte[] byteArray)
        {
            return new SoapHexBinary(byteArray).ToString();
        }

        public byte[] HexToByteArray(string hexString)
        {
            if (0 != (hexString.Length % 2))
            {
                throw new ApplicationException("Hex string must be multiple of 2 in length");
            }
            var byteCount = hexString.Length / 2;
            var byteValues = new byte[byteCount];
            for (var i = 0; i < byteCount; i++)
            {
                byteValues[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return byteValues;
        }

        public string GetStoredInitVector(string cipherText)
        {
            var hashedText = ComputeBasicHash(cipherText, "");
            var iv = _cipherCache.GetCipherTextAndVector(hashedText).InitVector;
            if (string.IsNullOrEmpty(iv))
            {
                iv = _cipherRepo.GetCipherTextAndVector(hashedText).InitVector;
            }
            return iv;
        }

        public CipherValues GetCipherData(string cipherText)
        {
            var hashedCipherText = ComputeBasicHash(cipherText, "");
            var cipherData = _cipherCache.GetCipherTextAndVector(hashedCipherText) ?? _cipherRepo.GetCipherTextAndVector(hashedCipherText);
            return cipherData;
        }
    }

    public class CipherValues
    {
        public string HashedCipherText { get; set; }
        public string InitVector { get; set; }
    }

    public interface ICipherCache
    {
        CipherValues GetCipherTextAndVector(string hashedCipherText);
        void SaveCipherTextAndVector(string hashedCipherText, string initVector);
    }

    public interface ICipherRepo
    {
        CipherValues GetCipherTextAndVector(string hashedCipherText);
        void SaveCipherTextAndVector(string hashedCipherText, string initVector);
    }
}
