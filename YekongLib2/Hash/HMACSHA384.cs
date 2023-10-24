using System.Security.Cryptography;
using System.Text;

namespace YekongLib2.Hash;
public class HMACSHA384 : IHashAlgorithm
{
    private System.Security.Cryptography.HMACSHA384 algorithm;

    public HMACSHA384()
    {
        algorithm = new System.Security.Cryptography.HMACSHA384();
    }

    public static string GetString(byte[] data)
    {
        var tmp = new HMACSHA384();
        tmp.Update(data);
        return tmp.GetHash();
    }
    
    public static string GetString(string data, Encoding encoding = null)
    {
        if (encoding == null)
        {
            encoding = Encoding.UTF8;
        }
        return GetString(encoding.GetBytes(data));
    }

    public void Update(byte[] data)
    {
        algorithm.TransformBlock(data, 0, data.Length, null, 0);
    }

    public void Update(byte[] data, int offset, int length)
    {
        algorithm.TransformBlock(data, offset, length, null, 0);
    }

    public string GetHash()
    {
        algorithm.TransformFinalBlock(new byte[0], 0, 0);
        byte[] hash = algorithm.Hash;
        algorithm.Clear();

        StringBuilder sb = new StringBuilder();
        foreach (byte b in hash)
        {
            sb.Append(b.ToString("x2"));
        }

        return sb.ToString();
    }

}