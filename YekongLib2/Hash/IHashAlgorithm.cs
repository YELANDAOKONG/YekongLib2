namespace YekongLib2.Hash;

public interface IHashAlgorithm
{
    public static string GetString(byte[] data)
    {
        return "";
    }
    public static string GetString(string data)
    {
        return "";
    }


    public void Update(byte[] data);
    
    public void Update(byte[] data, int offset, int length);
    
    public string GetHash();


}