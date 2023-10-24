using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace YekongLib2.Encryption;

public class TripleDES
{
    public static byte[] Encrypt(byte[] str, byte[] sKey, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
        byte[] inputByteArray = str;
        
        if (sKey.Length < des.KeySize / 8)
        {
            byte[] paddedKey = new byte[des.KeySize / 8];
            Array.Copy(sKey, paddedKey, sKey.Length);
            sKey = paddedKey;
        }
        else if (sKey.Length > des.KeySize / 8)
        {
            byte[] truncatedKey = new byte[des.KeySize / 8];
            Array.Copy(sKey, truncatedKey, truncatedKey.Length);
            sKey = truncatedKey;
        }
        
        byte[] iv = new byte[des.BlockSize / 8];
        Array.Copy(sKey, iv, iv.Length);
        des.Key = sKey;
        des.IV = iv;
        des.Mode = cipherMode;
        des.Padding = paddingMode;
        MemoryStream ms = new MemoryStream();
        CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(inputByteArray, 0, inputByteArray.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    public static byte[] Decrypt(byte[] pToDecrypt, byte[] sKey, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
        byte[] inputByteArray = pToDecrypt;
        
        if (sKey.Length < des.KeySize / 8)
        {
            byte[] paddedKey = new byte[des.KeySize / 8];
            Array.Copy(sKey, paddedKey, sKey.Length);
            sKey = paddedKey;
        }
        else if (sKey.Length > des.KeySize / 8)
        {
            byte[] truncatedKey = new byte[des.KeySize / 8];
            Array.Copy(sKey, truncatedKey, truncatedKey.Length);
            sKey = truncatedKey;
        }
        
        byte[] iv = new byte[des.BlockSize / 8];
        Array.Copy(sKey, iv, iv.Length);
        des.Key = sKey;
        des.IV = iv;
        des.Mode = cipherMode;
        des.Padding = paddingMode;
        MemoryStream ms = new MemoryStream();
        CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
        cs.Write(inputByteArray, 0, inputByteArray.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    
    public static string Encrypt(string str, string sKey, Encoding encoding = null, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        if (encoding == null)
        {
            encoding = Encoding.UTF8;
        }

        var bytes = Encrypt(encoding.GetBytes(str), encoding.GetBytes(sKey), cipherMode: cipherMode, paddingMode: paddingMode);
        return Convert.ToBase64String(bytes);
    }
    
    public static string Decrypt(string pToDecrypt, string sKey, Encoding encoding = null, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        if (encoding == null)
        {
            encoding = Encoding.UTF8;
        }
        var bytes = Decrypt(Convert.FromBase64String(pToDecrypt), encoding.GetBytes(sKey), cipherMode: cipherMode, paddingMode: paddingMode);
        return encoding.GetString(bytes);
    }


}