using NBitcoin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.IsolatedStorage;
using System.Threading;
using System.Xml.Serialization;

//This library exposes methods for saving objects safely in the protected space

namespace SecureStorage
{
    /// <summary>
    /// This class has been conceived to be able to save objects in a safe way, that is: The saved data of any application cannot be considered safe if it will be accessible in clear text to other applications or resident software. For encryption to be active, the library must be initialized using the Initializer class, enabling encryption (encryption is enabled by default).
    /// </summary>
    public class ObjectStorage
    {
        /// <summary>
        /// Initialized object storage using the Initializer class, enabling encryption (encryption is enabled by default).
        /// </summary>
        /// <param name="secureStorage">storage name</param>
        public ObjectStorage(Storage secureStorage) => _secureStorage = secureStorage;
        private readonly Storage _secureStorage;

        private string ObjExtension() => _secureStorage.Encrypyed ? ".cry" : ".xml";
        private const string CharNotAllowed = "*?/\\|<>'\"";
        private static string ObjFolder(object obj)
        {
            if (obj == null)
            {
                //Debugger.Break();
                throw new ArgumentException("obj null", "");
            }
            return ObjFolder(obj.GetType());
        }
        private string FileName(string objFolder, string key) => Path.Combine(_secureStorage.Domain, objFolder, key) + ObjExtension();
        private string DirectoryName(string objFolder) => Path.Combine(_secureStorage.Domain, objFolder);
        private static string ObjFolder(Type type)
        {
            var objFolder = type.FullName;
            if (objFolder != null && objFolder.Contains("Version="))
            {
                objFolder = type.Namespace + "+" + type.Name;
            }
            return Clear(objFolder);
        }
        /// <summary>
        /// This method is used to encrypt and securely save objects with their public properties. Only public properties will be saved via serializations, so it is important that the class has a parameterless constructor for deserialization.In case the class has only parameterized constructors, it will be necessary to add an empty parameterless constructor, otherwise the deserialization fails.
        /// </summary>
        /// <param name="obj">Object to save</param>
        /// <param name="key">Key used to save the object. This key will be used to upload the object in the future. If this parameter is omitted, then it will be automatically deduced from the Key or Id property of the employee, or the default j and y will be assigned.</param>
        /// <returns>The key used to save the object</returns>
        /// <exception cref="ArgumentException">Object to save</exception>
        public string SaveObject(object obj, string key = default)
        {
            if (key == null)
            {
                key = GetKey(obj);
                if (key == null)
                    key = DefaultKey;
            }
#if DEBUG
            if (!_secureStorage.Initialized)
                Debugger.Break(); // The library was not initialized !!
#endif
            if (key == null || key.IndexOfAny(CharNotAllowed.ToCharArray()) != -1)
            {
                Debugger.Break();//Invalid character in the key
                throw new ArgumentException("Invalid character in the key", "");
            }
            Serialize(obj, key);
            return key;
        }
        private const string DefaultKey = "_defaulr";

        private static string GetKey(object obj)
        {
            string[] keys = { "Id", "ID", "id", "Key", "key" };
            foreach (var key in keys)
            {
                var value = TryGetPropValue(obj, key);
                if (value != null)
                    return value.ToString();
            }
            return null;
        }

        private static object TryGetPropValue(object obj, string propName)
        {
            return obj.GetType().GetProperty(propName)?.GetValue(obj);
        }

        /// <summary>
        /// This method is used to load a previously saved object.
        /// </summary>
        /// <param name="type">The type of the object you want to load. Represents type declarations: class types, interface types, array types, value types, enumeration types, type parameters, generic type definitions, and open or closed constructed generic types</param>
        /// <param name="key">The key that was used to save the object</param>
        /// <param name="createIfNonexistent">Create a new instance if there is no object saved with the required key</param>
        /// <returns>saved object</returns>
        /// <exception cref="ArgumentException"></exception>
        public object LoadObject(Type type, string key = DefaultKey, bool createIfNonexistent = false)
        {
#if DEBUG
            if (!_secureStorage.Initialized)
                Debugger.Break(); // The library was not initialized !!
#endif
            if (key == null || key.IndexOfAny(CharNotAllowed.ToCharArray()) != -1)
            {
                Debugger.Break();//Invalid character in the key
                throw new ArgumentException("Invalid character in the key", "");
            }
            object obj;
            if (type == null)
            {
                Debugger.Break();//Type is null
                throw new ArgumentException("Type is null", "");
            }

            obj = Deserialize(key, type);
            return obj == null && createIfNonexistent ? Activator.CreateInstance(type) : obj;
        }
        /// <summary>
        /// Get all the keys used to save a certain type of objects.
        /// </summary>
        /// <param name="type">The type of object whose keys you want to get</param>
        /// <returns>The keys used to save the object</returns>
        public string[] GetAllKey(Type type)
        {
            var result = new List<string>();
            var objFolder = ObjFolder(type);
            if (Storage.IsoStore.DirectoryExists(DirectoryName(objFolder)))
            {
                var files = Storage.IsoStore.GetFileNames(Path.Combine(DirectoryName(objFolder), "*" + ObjExtension()));
                foreach (var file in files)
                    result.Add(file.Substring(0, file.Length - 4));
            }
            return result.ToArray();
        }
        /// <summary>
        /// Get all the save objects by the type it was saved.
        /// </summary>
        /// <param name="type">The type of object you want to get </param>
        /// <returns>The objects by type</returns>
        public object[] GetAllObjects(Type type)
        {
            var result = new List<object>();
            var keys = GetAllKey(type);
            foreach (var key in keys)
            {
                var obj = LoadObject(type, key);
                if (obj != null)
                    result.Add(obj);
            }
            return result.ToArray();
        }
        /// <summary>
        /// Delete the saved object.
        /// </summary>
        /// <param name="type">The type of object</param>
        /// <param name="key"> The key that was used to save the object</param>
        public void DeleteObject(Type type, string key)
        {
            lock (this)
            {
                for (int attempt = 0; attempt < Attempt; attempt++)
                {
                    try
                    {
                        var objFolder = ObjFolder(type);
                        if (Storage.IsoStore.FileExists(FileName(objFolder, key)))
                            Storage.IsoStore.DeleteFile(FileName(objFolder, key));

                        return;
                    }
                    catch (Exception ex)
                    {
                        Thread.Sleep(100);
                        Debugger.Break();
                        Debug.WriteLine(ex.Message);
                    }

                }
            }
        }

        /// <summary>
        /// Delete all the object of certain type
        /// </summary>
        /// <param name="type">The type of the object</param>
        public void DeleteAllObject(Type type)
        {
            lock (this)
            {
                for (int attempt = 0; attempt < Attempt; attempt++)
                {
                    try
                    {
                        var keys = GetAllKey(type);
                        foreach (var key in keys)
                        {
                            var objFolder = ObjFolder(type);
                            if (Storage.IsoStore.FileExists(FileName(objFolder, key)))
                                Storage.IsoStore.DeleteFile(FileName(objFolder, key));
                        }
                        return;
                    }
                    catch (Exception ex)
                    {
                        Thread.Sleep(100);
                        Debugger.Break();
                        Debug.WriteLine(ex.Message);
                    }
                }
            }
        }

        private static string Clear(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            string functionReturnValue = null;
            foreach (var chr in text.ToCharArray())
            {
                if (CharNotAllowed.IndexOf(chr) != -1)
                    functionReturnValue += "-";
                else
                    functionReturnValue += chr;
            }
            if (functionReturnValue != null && functionReturnValue.Length > 255)
            {
                Debugger.Break();
                throw new ArgumentException("File name too long", "");
            }
            return functionReturnValue;
        }
        const int Attempt = 10;
        private void Serialize(object obj, string key)
        {
            lock (Storage.IsoStore)
            {
                for (int attempt = 0; attempt < Attempt; attempt++)
                {
                    try
                    {
                        var objFolder = ObjFolder(obj);
                        var fileName = FileName(objFolder, key);
                        if (!Storage.IsoStore.DirectoryExists(DirectoryName(objFolder)))
                            Storage.IsoStore.CreateDirectory(DirectoryName(objFolder));
                        using (var stream = new IsolatedStorageFileStream(fileName, FileMode.Create, FileAccess.Write, Storage.IsoStore))
                        {
                            var serializer = new XmlSerializer(obj.GetType());
                            if (_secureStorage.Encrypyed)
                                using (var memoryStream = new MemoryStream())
                                {
                                    serializer.Serialize(memoryStream, obj);
                                    var bytes = memoryStream.ToArray();
                                    var encryptBytes = Cryptography.Encrypt(bytes, _secureStorage.CryptKey(key));
                                    stream.Write(encryptBytes, 0, encryptBytes.Length);
                                }
                            else
                                serializer.Serialize(stream, obj);
                        }
                        return;
                    }
                    catch (Exception ex)
                    {
                        Thread.Sleep(100);
                        Debugger.Break();
                        Debug.WriteLine(ex.Message);
                    }
                }
            }
        }

        private object Deserialize(string key, Type type)
        {
            lock (Storage.IsoStore)
            {

                var objFolder = ObjFolder(type);
                var fileName = FileName(objFolder, key);
                if (!Storage.IsoStore.FileExists(fileName)) return null;
                for (int attempt = 0; attempt < Attempt; attempt++)
                {
                    try
                    {
                        using (Stream stream = new IsolatedStorageFileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Inheritable, Storage.IsoStore))
                        {
                            var serializer = new XmlSerializer(type);
                            if (_secureStorage.Encrypyed)
                                using (var memoryStream = new MemoryStream())
                                {
                                    stream.CopyTo(memoryStream);
                                    var bytes = memoryStream.ToArray();
                                    try
                                    {
                                        bytes = Cryptography.Decrypt(bytes, _secureStorage.CryptKey(key));
                                    }
                                    catch (Exception)
                                    {
                                        // If it happens here, it means that data is saved with a different decryption key.
                                        // Uninstalling does not remove this data, so it will be deleted!				
                                        stream.Dispose();
                                        Storage.IsoStore.DeleteFile(fileName);
                                        return null;
                                    }
                                    return serializer.Deserialize(new MemoryStream(bytes));
                                }
                            else
                                return serializer.Deserialize(stream);
                        }
                        //   stream?.Dispose();
                    }
                    catch (Exception ex)
                    {
                        // if (ex.HResult == -2146233264) // opened by another task
                        Thread.Sleep(100);
                        Debug.WriteLine(ex.InnerException); // Probably some properties of the object class are not serializable. Use [XmlIgnore] to exclude it.
                        Debugger.Break();
//                        Storage.IsoStore.DeleteFile(fileName);
                    }
                }
            }
            return null;
        }
    }
}