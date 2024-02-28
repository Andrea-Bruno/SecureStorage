﻿using System;

namespace SecureStorage
{
    /// <summary>
    /// <para>The necessity and desire to secure personal information is one thing that everyone shares around the world in the recent times, ranging from businesses to governments to military structures. Data security is critical whether it is being stored, sent, or delivered. Data breaches, hacking, and lost or stolen devices can have catastrophic financial and reputational costs. The need for a Library to protect data generated and handled by applications arose from a desire to protect not only public structures, but also individual citizens, who are even more at risk if their freedom of expression, gender, religion, and any data relating to their person and loved ones is not protected. </para>
    /// <para>Any application that does not secure the data it generates and manages carries the risk of revealing sensitive information that can be used to profile users, scammers to invent scams, and hackers to carry out their plans to pirated programs. The information created by the applications can easily be gathered and marketed on the dark web. </para>
    /// <para>SecureStorage is a library that provides effective encryption to the apps that use it, making the data generated by it inaccessible and inviolable. </para>
    /// <para> Any application creates a large quantity of data; some of it serves just as a warning, while others are essential to the application's operation and users, and some of it, if interfered with, can allow the application and its content to be hacked.</para>
    /// <para>To protect yourself from malicious hackers and organizational data breaches, encrypt all data generated by the application and prevent it from being saved in a way that may be read externally. In the case that unwanted access is permitted to a computer network or storage device, other apps on the same device, or system applications designed with fraudulent purpose by the device's maker, encryption provides an extra level of protection. The hacker will be unable to access the application data encrypted through SecureStorage.</para>
    /// <para><b>What is encryption?</b></para>
    /// <para>Simply said, encryption transforms data entered into a digital device into gibberish-like pieces. The encrypted data becomes more unreadable and indecipherable as the encryption technique becomes more complex. Decryption, on the other hand, restores the encrypted data to its original state, making it readable again. Unencrypted data is referred to as normal data, and encrypted data is referred to as encrypted data.</para>
    /// <para><b>Software vs Hardware encryption </b></para>
    /// <para>Software encryption encrypts data on a logical disk using a number of software packages. A unique key is created and saved in the computer's memory when a drive is encrypted for the first time. A user passcode is used to encrypt the key. When a user enters the passcode, the key is unlocked, allowing access to the drive's unencrypted data. The drive also stores a copy of the key. When data is written to the drive, it is encrypted using the key before it is physically committed to the disk; software encryption works as an intermediate between application read / write data on the device. Before being given to the software, data read from the drive is decrypted using the same key.
    /// Hardware - level encryption is possible on some devices: Hardware - based encryption is used in Self - Encrypting Drives(SEDs), which takes a more comprehensive approach to encrypting user data. SEDs include an AES encryption chip that encrypts data before it is written to NAND media and decrypts it before it is read. Between the operating system loaded on the drive and the system BIOS is where hardware encryption takes place. An encryption key is generated and stored on NAND flash memory when the drive is encrypted for the first time. A custom BIOS is loaded when the system is first booted, prompting for a user password. The contents of the drive are decrypted and access to the operating system and user data is provided once the pass is entered.</para>
    /// <para>Self-encrypting drives also encrypt and decrypt data on the fly, with the built-in cryptographic chip encrypting and decrypting data before it is written to NAND flash memory. Because the encryption procedure does not use the host CPU, the performance penalty associated with software encryption is reduced. The encryption key is typically placed in the SSD's built-in memory at system startup, which complicates recovery and makes it less vulnerable to low-level attacks. This hardware-based encryption solution provides strong data security in the event that the device is lost, cannot be disabled, and has no performance impact. However, it is a type of low-level encryption that is completely transparent to the device that uses these storage units, as well as to all software programs that run on the device. As a result, this type of encryption does not protect the data of individual applications and users from other resident programs that can see all of the data stored in clear text. </para>
    /// <para>SecureStorage provides an additional layer of security for individuals who utilize primary hardware encrypted devices, rendering the data unreadable outside of the single program that created and is using it. </para>
    /// <para> The Advanced Encryption Standard (AES) is a cryptographic technique that is based on the Rijndael family of algorithms. It is now one of the most widely used encryption and decryption techniques. Vincent Rijmjen and Joan Daemen created the Rijndael algorithm, which is a block cipher. It's a symmetric-key algorithm, which means it encrypts and decrypts data with the same key. As a consequence of the NIST Advanced Encryption Standard competition, the Rijndael algorithm was chosen as an Advanced Encryption Standard and the successor to the Data Encryption Standard (DES). The competition was held in order to produce a new cryptographic standard as a replacement for the obsolete DES. Because to the modernization of computer technologies, the Data Encryption Standard's key length (56 bits) was insecure at the time. The Rijndael family of functions is represented by three algorithms in the AES standard. They have varying key lengths of 128, 192, and 256 bits, but they all use the same 128-bit block length. More variations of encryption algorithms, cyphers, and other cryptographic functions are included in the Rijndael family of hashing functions than in AES. The Advanced Encryption Standard was designed to work equally well in software and hardware implementations. With the deployment of the substitution–permutation network design, it was possible. This network design is similar to the Feistel network, which was utilized in DES, but it is faster to compute on both hardware and software, which was critical given DES's software implementation inefficiency. </para>
    /// <para>Our cryptography is the same as that used in Bitcoin, which has been put to the test by hackers all around the world without ever being broken: Breaking this form of cryptography would give you access to coins stored in wallets, which no one has ever done before. </para>
    /// <para>The Advanced Encryption Algorithm (AES256) is an AES algorithm with a key length of 256 bits.The computational difficulty of the decryption is affected by the length of the AES version. The key recovery for AES 256-encrypted data requires more computational power than the 128 and 192-bit variants. The biclique attack, for example, can decrypt AES128 with a computational complexity of 2126. The computational complexity of biclique attacks on AES 192 and AES 256 are 2189.9 and 2254.3, respectively.However, for every key length, real execution of the attacks on the AES-protected data is currently impractical. All of the AES attacks are hypothetical. Every known AES attack would take millions of years to complete, regardless of the algorithm's key length.</para>
    /// </summary>
    /// 


    /// <summary>
    /// This class is used to save in an encrypted and secure way the values, which can be used by any application that needs to store parameters, such as configuration values, flags, names, and variables that you do not want to be lost after restarting of the application
    /// </summary>
    public class Values
    {
        private readonly Storage _initializer;
        internal Values(Storage initializer)
        {
            _initializer = initializer;
        }

        // ====================== bool ======================

        /// <summary>
        /// Permanently save the value of a variable, for possible use after reloading the application
        /// </summary>
        /// <param name="name">Name to assign to the variable</param>
        /// <param name="value">The value of the variable to save </param>
        public void Set(string name, bool value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <summary>
        /// Load a previously saved value of a variable, if it has not been previously saved then the returned value will be by default indicated in the parameter
        /// </summary>
        /// <param name="name">The name assigned to the variable</param>
        /// <param name="defaultValue">This value will be returned if the variable has never been previously saved</param>
        /// <returns>The value of the previously saved variable, or the default value</returns>
        public bool Get(string name, bool defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(bool), "v_" + name);
            return (bool?)value ?? defaultValue;
        }

        // ====================== string ======================

        /// <inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, string value)
        {
            if (value == null)
                _initializer.ObjectStorage.DeleteObject(typeof(string), "v_" + name);
            else
                _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public string Get(string name, string defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(string), "v_" + name);
            return (string)value ?? defaultValue;
        }

        // ====================== int ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, int value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        
        ///<inheritdoc cref="Set(string, bool)"/>
        public int Get(string name, int defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(int), "v_" + name);
            return (int?)value ?? defaultValue;
        }

        // ====================== unit ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, uint value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public uint Get(string name, uint defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(uint), "v_" + name);
            return (uint?)value ?? defaultValue;
        }

        // ====================== long ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, long value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public long Get(string name, long defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(long), "v_" + name);
            return (long?)value ?? defaultValue;
        }

        // ====================== ulong ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, ulong value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public ulong Get(string name, ulong defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(ulong), "v_" + name);
            return (ulong?)value ?? defaultValue;
        }

        // ====================== short ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, short value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public short Get(string name, short defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(short), "v_" + name);
            return (short?)value ?? defaultValue;
        }

        // ====================== ushort ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, ushort value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public ushort Get(string name, ushort defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(ushort), "v_" + name);
            return (ushort?)value ?? defaultValue;
        }

        // ====================== double ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, double value)
        {
            _initializer.ObjectStorage.SaveObject(value, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public double Get(string name, double defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(double), "v_" + name);
            return (double?)value ?? defaultValue;
        }

        // ====================== DateTime ======================

        ///<inheritdoc cref="Set(string, bool)"/>
        public void Set(string name, DateTime value)
        {
            if (value == null)
                _initializer.ObjectStorage.DeleteObject(typeof(DateTime), "v_" + name);
            else
                _initializer.ObjectStorage.SaveObject(value.Ticks, "v_" + name);
        }
        /// <inheritdoc cref="Get(string, bool)"/>
        public DateTime Get(string name, DateTime defaultValue = default)
        {
            var value = _initializer.ObjectStorage.LoadObject(typeof(DateTime), "v_" + name);
            return value == null ? defaultValue : new DateTime((long)value);
        }

        /// <summary>
        /// Clear a previously saved value with a key
        /// </summary>
        /// <param name="name">Key of value to delete</param>
        /// <param name="type">Type of value to delete</param>
        public void Delete(string name, Type type)
        {
            _initializer.ObjectStorage.DeleteObject(type, "v_" + name);
        }
    }


}
