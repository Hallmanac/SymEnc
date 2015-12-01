using System.Security.Cryptography;

namespace SymEnc.Core
{
	/// <summary>
	/// Symmetric encryption helpers along with hashing and random number generators.
	/// </summary>
	public interface ISymmetricEncyrptionSvc
	{
		/// <summary>
		///     <para>MAKE SURE YOUR KEY IS UNIQUE FOR YOUR APPLICATION!!</para>
		///     <example>Example-Key = 16CF22659BB1DE3038B2058C98687A21ED9F103A1162BC32E35BCCC46A905C5B</example>
		///     <para>
		///         Generate your key using the console application located with the source code at
		///         https://github.com/Hallmanac/SymEnc.
		///         This key is used for encrypting/decrypting site data and is used as the default key when no key is given.
		///         For use cases that require interaction outside of the site, we would generate a new random (private) key for
		///         each
		///         instance where we would store the generated key as well as the client app would store the generated private
		///         key.
		///     </para>
		/// </summary>
		string Default256BitKey { get; }

		/// <summary>
		///     Creates a RijndaelManaged cipher based on the given key material with a default 256 block size. If no key is given
		///     then the <see cref="SymmetricEncyrptionSvc.Default256BitKey" /> is used.
		/// </summary>
		RijndaelManaged CreateCipher(string key = "", int blockSize = 256);

		/// <summary>
		///     Encrypts a string using the given key. To Decrypt you will need the proper initialization vector that gets randomly
		///     generated
		///     for each encryption process (i.e. different every time the encryption is run). This will happen automatically in
		///     our
		///     Decrypt
		///     method on this class because we're prefixing those initialization vectors with the encrypted text.
		/// </summary>
		/// <param name="plainText">Text value to be encrypted</param>
		/// <param name="key">MUST be a hex string based on a 256 bit byte array (i.e. new byte[32])</param>
		/// <param name="blockSize">Size of block used in the Rijndael algorithm</param>
		/// <returns>Encrypted Hexadecimal string of the given <see cref="plainText" /></returns>
		string Encrypt(string plainText, string key = "", int blockSize = 256);

		/// <summary>
		///     Decrypts a given cipher text based on the provided key material. The initialization vector should be prefixed to
		///     the
		///     cipher text followed
		///     by an underscore for delimiting.
		/// </summary>
		/// <param name="cipherText">Text to be decrypted</param>
		/// <param name="key">MUST be a hex string based on a 256 bit byte array (i.e. new byte[32])</param>
		/// <param name="blockSize">Size of block used in the Rijndael algorithm</param>
		/// <returns></returns>
		string Decrypt(string cipherText, string key = "", int blockSize = 256);

		/// <summary>
		///     Checks to see if the given text is encrypted based on the logic in this class.
		/// </summary>
		bool IsEncrypted(string text);

		/// <summary>
		///     Generates random, non-zero bytes using the RNGCryptoServiceProvider
		/// </summary>
		/// <param name="buffer">Length of random bytes to be generated.</param>
		void GenerateRandomBytes(byte[] buffer);

		/// <summary>
		///     Generates a random byte array key based on the byte length given and returns it as a hexadecimal string.
		/// </summary>
		/// <param name="byteLength">Length of Byte array used in the random generator</param>
		/// <returns>Hexadecimal text representation of the randomly generated bytes.</returns>
		string GenerateHexKeyFromByteLength(int byteLength);

		/// <summary>
		///   Generates a random byte array key based on the byte length given and returns it as a Base64 encoded string.
		/// </summary>
		/// <param name="byteLength">Length of Byte array used in the random generator</param>
		/// <returns>Base64 encoded text representation of the randomly generated bytes.</returns>
		string GenerateBase64KeyFromByteLength(int byteLength);

        /// <summary>
        /// Generates a crypto random 64 bit number (does NOT use the .NET random number generator).
        /// </summary>
        /// <param name="byteLength"></param>
        /// <returns>A 19 digit random number</returns>
        long GenerateRandom64BitNumberFromByteLength(int byteLength);

        /// <summary>
        /// Generates a crypto random 32 bit number (does NOT use the .NET random number generator).
        /// </summary>
        /// <param name="byteLength"></param>
        /// <returns>a ten digit random number</returns>
		int GenerateRandom32BitNumberFromByteLength(int byteLength);

		/// <summary>
		///     Generates a random 256 bit key (in a byte array) and returns it as a hexadecimal string.
		/// </summary>
		/// <returns>A hexadecimal string based on the randomly generated 256 bit key byte array</returns>
		string Generate256BitKey();

		/// <summary>
		///     This will compute a basic SHA1 hash for uses within this Encryption Service class. This hash is not recommended for
		///     true security use cases. For great security checkout PWDTK.Net https://github.com/Thashiznets/PWDTK.NET?source=c
		/// </summary>
		string ComputeBasicHash(string textToHash, string salt = "");

		/// <summary>
		///     Converts a given byte array into a hexadecimal string.
		/// </summary>
		string BytesToHexString(byte[] byteArray);

		/// <summary>
		///     Converts a given hexadecimal string into a byte array. The Hex string must be in multiple of 2's in length or it
		///     will
		///     throw an exception.
		/// </summary>
		byte[] HexToByteArray(string hexString);

		/// <summary>
		///     Computes a hash based on the HMACSHA1 algorithm using the given key.
		/// </summary>
		string ComputeHmacSha1ForHex(string textToHash, string key = "");

		/// <summary>
		///     Computes a hash based on the HMACSHA256 algorithm using the given key.
		/// </summary>
		string ComputeHmacSha256ForHex(string textToHash, string key = "");

		/// <summary>
		///     Computes a hash based on the HMACSHA1 algorithm using the given key and returns a Base64 encoded string.
		/// </summary>
		string ComputeHmacSha1ForBase64(string textToEncode, string key = "");

		/// <summary>
		///     Computes a hash based on the HMACSHA256 algorithm using the given key and returns a Base64 encoded string.
		/// </summary>
		string ComputeHmacSha256ForBase64(string textToEncode, string key = "");
	}
}