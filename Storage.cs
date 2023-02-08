using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.IsolatedStorage;
using System.Security.Cryptography;
using System.Text;
using NBitcoin;

namespace SecureStorage
{
    /// <summary>
    /// Provides the library initializer, and object instances that handle saving data in various formats
    /// </summary>
    public class Storage
    {
        /// <summary>
        /// Prepares the library for using cryptography. Before using the library, initialization is mandatory!
        /// </summary>
        /// <param name="domain">The domain allows you to use multiple instances of the library. Then use different domains to have multiple instances</param>
        /// <param name="getSecureKeyValue">Function to get keys safely save in hardware.</param>
        /// <param name="setSecureKeyValue">Secure function provided by the hardware to be able to save keys</param>
        /// <param name="encrypted">Enable encryption (by default it is active and it is recommended not to delete it to keep your data safe)</param>
        public Storage(string domain, Func<string, string> getSecureKeyValue = null, SetKeyValueSecure setSecureKeyValue = null, bool encrypted = true)
        {
            Func<string, string> getKeyValue;
            SetKeyValueSecure setKeyValue;
            Domain = BitConverter.ToUInt64(_hashAlgorithm.ComputeHash(Encoding.Unicode.GetBytes(domain)), 0).ToString("x");
            if (Domains.Contains(Domain))
                throw new Exception("Storage already instantiated with this domain: " + domain);
            Domains.Add(Domain);
            DataStorage = new DataStorage(this);
            ObjectStorage = new ObjectStorage(this);
            Values = new Values(this);
            void UseInternalAlgorithms()
            {
                var hash = _hashAlgorithm.ComputeHash(Encoding.Unicode.GetBytes(Domain + Environment.MachineName + Environment.UserName));
                DefaultEncrypter = new Key(hash);
                setKeyValue = (key, value) => SetKeyValue_Default(Domain + "." + key, value);
                getKeyValue = key => GetKeyValue_Default(Domain + "." + key);
            }
            if (setSecureKeyValue != null && getSecureKeyValue != null)
            {
                setKeyValue = (key, value) => setSecureKeyValue(Domain + "." + key, value);
                getKeyValue = key => getSecureKeyValue(Domain + "." + key);
            }
            else
                UseInternalAlgorithms();

            //Check that saving keys and values are working correctly
            try
            {
                setKeyValue("test", "test");
                if (getKeyValue("test") == "test")
                {
                    setKeyValue("test", "");
                }
                SecureKeyValueCapability = true;
            }
            catch (Exception ex)
            {
                SecureKeyValueCapability = false;
                UseInternalAlgorithms();
                Debug.WriteLine(ex.ToString());
                Debugger.Break();
            }

            Encrypyed = encrypted;
            var h5 = new byte[5];
            Array.Copy(_hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(Environment.MachineName)), h5, h5.Length);
            var keyName = BitConverter.ToString(h5).Replace("-", "");
            var baseKey = getKeyValue(keyName);
            if (string.IsNullOrEmpty(baseKey))
            {
                var rnd = new Random();
                var bytes = new byte[32];
                rnd.NextBytes(bytes);
                baseKey = BitConverter.ToString(bytes);
                baseKey += Environment.MachineName + Environment.UserName;
                var hash = _hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(baseKey));
                baseKey = BitConverter.ToString(hash).Replace("-", "");
                setKeyValue(keyName, baseKey);
            }
            _baseKey = new byte[baseKey.Length / 2];
            for (var i = 0; i < baseKey.Length; i += 2)
                _baseKey[i / 2] = Convert.ToByte(baseKey.Substring(i, 2), 16);
            Initialized = true;
        }
        /// <summary>
        /// Call Dispose to free resources explicitly
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        private bool IsDisposed;

        /// <summary>
        /// Implement dispose to free resources
        /// </summary>
        /// <param name="disposedStatus"></param>
        protected virtual void Dispose(bool disposedStatus)
        {
            if (!IsDisposed)
            {
                IsDisposed = true;
            }
            if (Domains.Contains(Domain))
                Domains.Remove(Domain);
        }

        private static readonly HashSet<string> Domains = new HashSet<string>();
        /// <summary>
        /// Delete all the directory with all the content in it.
        /// </summary>
        public void Destroy()
        {
            try
            {
                DeleteDirectoryRecursively(IsoStore, Domain);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// Delete a specific file from a directory.
        /// </summary>
        /// <param name="storageFile">Name of the file to delete</param>
        /// <param name="dirName">Directory Name to delete the file from it</param>
        private static void DeleteDirectoryRecursively(IsolatedStorageFile storageFile, string dirName)
        {
            var pattern = dirName + @"\*";
            var files = storageFile.GetFileNames(pattern);
            foreach (var fName in files)
            {
                storageFile.DeleteFile(Path.Combine(dirName, fName));
            }
            var dirs = storageFile.GetDirectoryNames(pattern);
            foreach (var dName in dirs)
            {
                DeleteDirectoryRecursively(storageFile, Path.Combine(dirName, dName));
            }
            storageFile.DeleteDirectory(dirName);
        }
        /// <summary>
        /// The location of the secure storage
        /// </summary>
        internal static readonly IsolatedStorageFile IsoStore = GetStorage();
        // internal static readonly IsolatedStorageFile IsoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Assembly | IsolatedStorageScope.Domain, null, null);
        private static IsolatedStorageFile GetStorage()
        {
            IsolatedStorageFile storage;
            try
            {
                storage = IsolatedStorageFile.GetMachineStoreForApplication();
                _ = storage.AvailableFreeSpace;
            }
            catch (Exception)
            {
                storage = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Assembly | IsolatedStorageScope.Domain, null, null);
                _ = storage.AvailableFreeSpace;
            }
            return storage;
        }

        internal bool Initialized;
        /// <summary>
        /// A value that indicates for the device, the manager that keeps the keys works regularly. A false value indicates that there are serious security problems.
        /// </summary>
        public readonly bool SecureKeyValueCapability;

        /// <summary>
        /// Functionality to save binary data
        /// </summary>
        public readonly DataStorage DataStorage;

        /// <summary>
        /// Functionality to save objects
        /// </summary>
        public readonly ObjectStorage ObjectStorage;

        /// <summary>
        /// Functionality to save values
        /// </summary>
        public readonly Values Values;
        internal readonly bool Encrypyed;
        internal readonly string Domain;

        /// <summary>
        /// Delegate of function to securely save a key-value pair, which will then be read with GetKeyValue
        /// </summary>
        public delegate void SetKeyValueSecure(string key, string value);

        // OLD VERSION
        //internal readonly IsolatedStorageFile IsoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User, null, null);
        private readonly HashAlgorithm _hashAlgorithm = SHA256.Create();
        private readonly byte[] _baseKey;

        internal byte[] CryptKey(string key)
        {
#if DEBUG
            if (_baseKey == null)
            {
                Debug.WriteLine("Please initialize this library before using it. Use InitializeAsync");
                Debugger.Break();
            }
#endif
            var keyByte = Encoding.ASCII.GetBytes(key);
            var fullKey = new byte[(_baseKey == null ? 0 : _baseKey.Length) + keyByte.Length];
            _baseKey?.CopyTo(fullKey, 0);
            var index = _baseKey == null ? 0 : _baseKey.Length;
            keyByte.CopyTo(fullKey, index);
            var cryptKey = _hashAlgorithm.ComputeHash(fullKey);
            return cryptKey;
        }

        private Key DefaultEncrypter;
        /// <summary>
        /// Secure function provided by the hardware to be able to save keys
        /// </summary>
        /// <param name="key">Key to identify the users and will be used to save and delete data on the device</param>
        /// <param name="value"> Encrypted Key Value</param>
        public void SetKeyValue_Default(string key, string value)
        {
            var filename = BitConverter.ToString(_hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(key + Domain))).Replace("-", "");
            try
            {
                if (value == null)
                {
                    if (IsoStore.FileExists(Path.Combine(".", filename)))
                        IsoStore.DeleteFile(Path.Combine(".", filename));
                    return;
                }
                var fileStream = IsoStore.OpenFile(Path.Combine(".", filename), FileMode.Create);
                var buffer = Encoding.Unicode.GetBytes(value);
                var encrypted = DefaultEncrypter.PubKey.Encrypt(buffer);
                fileStream.Write(encrypted, 0, encrypted.Length);
                fileStream.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("There is some problem with saving encrypted values: " + e.Message);
                Debugger.Break();
            }
        }
        private string GetKeyValue_Default(string key)
        {
            var filename = BitConverter.ToString(_hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(key + Domain))).Replace("-", "");
            try
            {
                if (IsoStore.FileExists(Path.Combine(".", filename)))
                {
                    var fileStream = IsoStore.OpenFile(Path.Combine(".", filename), FileMode.Open);
                    byte[] buffer;
                    using (var reader = new BinaryReader(fileStream))
                    {
                        buffer = reader.ReadBytes((int)fileStream.Length);
                    }
                    // var buffer = new byte[fileStream.Length];
                    // fileStream.Read(buffer, 0, buffer.Length);
                    fileStream.Close();

                    var decrypted = DefaultEncrypter.Decrypt(buffer);
                    return Encoding.Unicode.GetString(decrypted);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("There is some problem with recovering the encrypted values: " + e.Message);
                Debugger.Break();
            }
            return null;
        }

    }
}