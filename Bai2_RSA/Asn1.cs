using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA;

/// <summary>
/// Bộ phân tích DER/ASN.1 tối giản để "xem PEM" và giải thích ý nghĩa từng byte.
/// </summary>
internal static class Asn1
{
    public static byte[] PemToDer(string pem, out string label)
    {
        var f = PemEncoding.Find(pem);
        label = pem[f.Label].ToString();
        return Convert.FromBase64String(pem[f.Base64Data].ToString());
    }

    public static string HexDump(byte[] d)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < d.Length; i += 16)
        {
            int n = Math.Min(16, d.Length - i);
            sb.Append($"{i:X4}  ");
            for (int j = 0; j < 16; j++)
                sb.Append(j < n ? d[i + j].ToString("X2") + " " : "   ");
            sb.Append(" ");
            for (int j = 0; j < n; j++)
            {
                char c = (char)d[i + j];
                sb.Append(c >= 32 && c < 127 ? c : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public static string Dump(byte[] d)
    {
        var sb = new StringBuilder();
        try { Parse(d, 0, d.Length, 0, sb); }
        catch (Exception ex) { sb.AppendLine("(Lỗi phân tích: " + ex.Message + ")"); }
        return sb.ToString();
    }

    private static void Parse(byte[] d, int start, int end, int depth, StringBuilder sb)
    {
        int pos = start;
        while (pos < end)
        {
            int off = pos;
            byte tag = d[pos++];
            int first = d[pos++];
            int len, lenSize;
            if ((first & 0x80) == 0) { len = first; lenSize = 1; }
            else
            {
                int n = first & 0x7F;
                if (n == 0 || n > 4) throw new Exception("độ dài không hợp lệ tại offset " + off);
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | d[pos++];
                lenSize = 1 + n;
            }
            if (len < 0 || pos + len > end) throw new Exception("độ dài vượt quá dữ liệu tại offset " + off);

            string indent = new string(' ', depth * 2);
            string lenHex = Convert.ToHexString(d, off + 1, lenSize);
            sb.Append($"{indent}[{off:D4}] tag={tag:X2} {TagName(tag)}, byte độ dài={lenHex} => {len} byte");

            if ((tag & 0x20) != 0)    // kiểu cấu trúc: chứa phần tử con
            {
                sb.AppendLine(" (cấu trúc, chứa các phần tử con)");
                Parse(d, pos, pos + len, depth + 1, sb);
            }
            else
            {
                switch (tag)
                {
                    case 0x02:   // INTEGER
                        {
                            var big = new BigInteger(d.AsSpan(pos, len), isUnsigned: true, isBigEndian: true);
                            sb.Append($" | số nguyên {big.GetBitLength()} bit");
                            if (len <= 4) sb.Append($" = {big} (version hoặc số mũ công khai e)");
                            sb.AppendLine();
                            sb.AppendLine($"{indent}      giá trị (hex): {Short(d, pos, len)}");
                            break;
                        }
                    case 0x03:   // BIT STRING
                        if (len > 1 && d[pos + 1] == 0x30)
                        {
                            sb.AppendLine($" | số bit thừa={d[pos]} (chứa cấu trúc bên trong)");
                            Parse(d, pos + 1, pos + len, depth + 1, sb);
                        }
                        else sb.AppendLine($" | {Short(d, pos, len)}");
                        break;
                    case 0x04:   // OCTET STRING
                        if (len > 0 && d[pos] == 0x30)
                        {
                            sb.AppendLine(" | (chứa cấu trúc bên trong: khoá riêng RSA)");
                            try { Parse(d, pos, pos + len, depth + 1, sb); }
                            catch { sb.AppendLine($"{indent}  {Short(d, pos, len)}"); }
                        }
                        else sb.AppendLine($" | {Short(d, pos, len)}");
                        break;
                    case 0x05:
                        sb.AppendLine(" | NULL (tham số rỗng)");
                        break;
                    case 0x06:
                        sb.AppendLine($" | OID {Oid(d, pos, len)}");
                        break;
                    default:
                        sb.AppendLine($" | {Short(d, pos, len)}");
                        break;
                }
            }
            pos += len;
        }
    }

    private static string Short(byte[] d, int pos, int len)
    {
        int n = Math.Min(len, 24);
        return Convert.ToHexString(d, pos, n) + (len > n ? $"... ({len} byte)" : "");
    }

    private static string TagName(byte tag) => tag switch
    {
        0x01 => "BOOLEAN",
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        0x0C => "UTF8String",
        0x13 => "PrintableString",
        0x30 => "SEQUENCE",
        0x31 => "SET",
        _ => (tag & 0x80) != 0 ? "context-specific" : "tag khác",
    };

    private static string Oid(byte[] d, int pos, int len)
    {
        if (len == 0) return "";
        var parts = new List<string> { (d[pos] / 40).ToString(), (d[pos] % 40).ToString() };
        long v = 0;
        for (int i = 1; i < len; i++)
        {
            v = (v << 7) | (uint)(d[pos + i] & 0x7F);
            if ((d[pos + i] & 0x80) == 0) { parts.Add(v.ToString()); v = 0; }
        }
        string oid = string.Join(".", parts);
        return oid == "1.2.840.113549.1.1.1" ? oid + " (rsaEncryption)" : oid;
    }
}
