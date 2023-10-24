using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace YekongLib2.Encryption;

public class DES
{
    public static byte[] Encrypt(byte[] str, byte[] sKey)
    {
        DESCryptoServiceProvider des = new DESCryptoServiceProvider();
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
        des.Key = sKey;
        des.IV = sKey;
        MemoryStream ms = new MemoryStream();
        CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(inputByteArray, 0, inputByteArray.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }
    
    public static byte[] Decrypt(byte[] pToDecrypt, byte[] sKey)
    {
        DESCryptoServiceProvider des = new DESCryptoServiceProvider();
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
        des.Key = sKey;
        des.IV = sKey;
        MemoryStream ms = new MemoryStream();
        CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
        cs.Write(inputByteArray, 0, inputByteArray.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    
    public static string Encrypt(string str, string sKey, Encoding encoding = null)
    {
        if (encoding == null)
        {
            encoding = Encoding.UTF8;
        }

        var bytes = Encrypt(encoding.GetBytes(str), encoding.GetBytes(sKey));
        return Convert.ToBase64String(bytes);
    }
    
    public static string Decrypt(string pToDecrypt, string sKey, Encoding encoding = null)
    {
        if (encoding == null)
        {
            encoding = Encoding.UTF8;
        }
        var bytes = Decrypt(Convert.FromBase64String(pToDecrypt), encoding.GetBytes(sKey));
        return encoding.GetString(bytes);
    }


}