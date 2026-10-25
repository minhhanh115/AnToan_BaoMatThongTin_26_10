using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA;

/// <summary>
/// Bài 2 - RSA (.NET WinForms): sinh khoá, PEM, mã hoá/giải mã, đo tốc độ,
/// băm SHA-256 và chữ ký số (có đề xuất chữ ký ngẫu nhiên hoá bằng RSASSA-PSS).
/// </summary>
public class MainForm : Form
{
    // ---------- Khoá đang dùng (dạng PEM) ----------
    private string _pubPem;
    private string _privPem;

    private readonly List<Button> _buttons = new();
    private Label _status;

    // Tab 1-2
    private ComboBox cboBits;
    private TextBox txtPubPem, txtPrivPem, txtPemView, txtAsn1, txtParams;
    // Tab 3
    private TextBox txtData, txtCipherOut, txtDecryptOut, txtCipherPath;
    private CheckBox chkBase64;
    private Label lblLimit;
    // Tab 4
    private NumericUpDown numIter;
    private TextBox txtBench;
    // Tab 5
    private TextBox txtHashIn, txtHashOut, txtHashLog;
    private byte[] _prevHash;
    private string _prevInput;
    // Tab 6
    private TextBox txtSignData, txtSignOut;

    public MainForm()
    {
        Text = "Bài 2 - RSA, SHA-256, Chữ ký số";
        Width = 1080;
        Height = 800;
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildKeyTab());
        tabs.TabPages.Add(BuildPemTab());
        tabs.TabPages.Add(BuildCryptTab());
        tabs.TabPages.Add(BuildBenchTab());
        tabs.TabPages.Add(BuildHashTab());
        tabs.TabPages.Add(BuildSignTab());
        root.Controls.Add(tabs, 0, 0);

        _status = new Label { AutoSize = true, Dock = DockStyle.Fill, Padding = new Padding(8, 4, 8, 4) };
        root.Controls.Add(_status, 0, 1);
        Controls.Add(root);
        UpdateStatus();
    }

    private Button Btn(string text, EventHandler h)
    {
        var b = Ui.Button(text, h);
        _buttons.Add(b);
        return b;
    }

    private void UpdateStatus()
    {
        string pub = _pubPem != null ? $"có ({KeyBits(_pubPem)} bit)" : "chưa có";
        string priv = _privPem != null ? "có" : "chưa có";
        _status.Text = $"Khoá đang dùng →  Public key: {pub}   |   Private key: {priv}";
    }

    private static int KeyBits(string pem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa.KeySize;
    }

    private RSA Pub()
    {
        if (_pubPem == null) throw new Exception("Chưa có public key. Hãy sinh khoá hoặc nạp file PEM.");
        var r = RSA.Create();
        r.ImportFromPem(_pubPem);
        return r;
    }

    private RSA Priv()
    {
        if (_privPem == null) throw new Exception("Chưa có private key. Hãy sinh khoá hoặc nạp file PEM chứa private key.");
        var r = RSA.Create();
        r.ImportFromPem(_privPem);
        return r;
    }

    private void Guard(Action a)
    {
        try { a(); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    // =====================================================================
    //  Tab 1: Sinh khoá + xuất PEM
    // =====================================================================
    private TabPage BuildKeyTab()
    {
        var page = new TabPage("1-2. Sinh khoá & xuất PEM");
        var t = Ui.Column(page);

        cboBits = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
        cboBits.Items.AddRange(new object[] { "1024", "2048", "3072", "4096" });
        cboBits.SelectedItem = "2048";

        Ui.Auto(t, Ui.Bar(Ui.Label("Độ dài khoá RSA (bit):"), cboBits,
            Btn("Sinh cặp khoá", (_, _) => Guard(GenerateKeys)),
            Btn("Lưu public.pem...", (_, _) => Guard(() => SavePem(_pubPem, "public.pem"))),
            Btn("Lưu private.pem...", (_, _) => Guard(() => SavePem(_privPem, "private.pem")))));

        Ui.Auto(t, Ui.Label("Public key (định dạng SubjectPublicKeyInfo - 'BEGIN PUBLIC KEY'):"));
        txtPubPem = Ui.Text(true);
        Ui.Fill(t, txtPubPem, 35);
        Ui.Auto(t, Ui.Label("Private key (định dạng PKCS#8 - 'BEGIN PRIVATE KEY'). Phải giữ bí mật!"));
        txtPrivPem = Ui.Text(true);
        Ui.Fill(t, txtPrivPem, 65);
        return page;
    }

    private void GenerateKeys()
    {
        int bits = int.Parse((string)cboBits.SelectedItem);
        UseWaitCursor = true;
        try
        {
            using var rsa = RSA.Create(bits);
            _pubPem = rsa.ExportSubjectPublicKeyInfoPem();
            _privPem = rsa.ExportPkcs8PrivateKeyPem();
        }
        finally { UseWaitCursor = false; }
        _lastLoaded = null;
        txtPubPem.Text = _pubPem;
        txtPrivPem.Text = _privPem;
        UpdateStatus();
    }

    private static void SavePem(string pem, string defaultName)
    {
        if (pem == null) throw new Exception("Chưa có khoá để lưu.");
        using var sfd = new SaveFileDialog { Filter = "PEM (*.pem)|*.pem|All files|*.*", FileName = defaultName };
        if (sfd.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(sfd.FileName, pem);
        MessageBox.Show("Đã lưu: " + sfd.FileName);
    }

    // =====================================================================
    //  Tab 2: Xem PEM / nhập PEM
    // =====================================================================
    private const string PemExplain =
@"CẤU TRÚC FILE PEM
- Dòng '-----BEGIN ... -----' và '-----END ... -----': nhãn cho biết loại dữ liệu (PUBLIC KEY, PRIVATE KEY, RSA PRIVATE KEY...).
- Phần giữa là Base64 của dữ liệu nhị phân DER (mỗi dòng 64 ký tự, 4 ký tự Base64 = 3 byte).
- DER là mã hoá ASN.1 dạng TLV: mỗi phần tử gồm  Tag (1 byte) | Length | Value.
    30 = SEQUENCE (nhóm các phần tử)    02 = INTEGER (số nguyên lớn)    03 = BIT STRING
    04 = OCTET STRING                   05 = NULL                       06 = OBJECT IDENTIFIER
- Length: nếu < 0x80 thì chính là độ dài; nếu byte đầu dạng 0x8N thì N byte sau là độ dài (vd 82 01 0A = 266 byte).
- INTEGER dương có bit cao = 1 thì được thêm byte 00 ở đầu (vì vậy n 2048 bit thường dài 257 byte, bắt đầu bằng 00).
- Public key (SPKI):  SEQUENCE { SEQUENCE { OID rsaEncryption, NULL },  BIT STRING { SEQUENCE { n, e } } }
- Private key (PKCS#8): SEQUENCE { version(0), SEQUENCE { OID, NULL }, OCTET STRING { SEQUENCE { 0, n, e, d, p, q, dP, dQ, qInv } } }
    n = p*q (modulus)   e = số mũ công khai   d = số mũ bí mật   p,q = hai số nguyên tố
    dP = d mod (p-1)   dQ = d mod (q-1)   qInv = q^-1 mod p   (3 giá trị cuối để giải mã nhanh bằng định lý số dư Trung Hoa)";

    private TabPage BuildPemTab()
    {
        var page = new TabPage("3-4. Xem / nhập PEM (n, e, d...)");
        var t = Ui.Column(page);

        Ui.Auto(t, Ui.Bar(
            Btn("Nhập file PEM (public hoặc private)...", (_, _) => Guard(LoadPemFromDialog)),
            Btn("Xem khoá đang dùng", (_, _) => Guard(ShowCurrent))));

        var explain = Ui.Text(true);
        explain.WordWrap = true;
        explain.Text = PemExplain.Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 170));
        explain.Dock = DockStyle.Fill;
        t.Controls.Add(explain);

        Ui.Auto(t, Ui.Label("Nội dung PEM:"));
        txtPemView = Ui.Text(true);
        Ui.Fill(t, txtPemView, 18);
        Ui.Auto(t, Ui.Label("Phân tích ASN.1/DER (ý nghĩa từng nhóm byte):"));
        txtAsn1 = Ui.Text(true);
        Ui.Fill(t, txtAsn1, 40);
        Ui.Auto(t, Ui.Label("Tham số RSA đọc được (n, e, d, p, q, ...):"));
        txtParams = Ui.Text(true);
        Ui.Fill(t, txtParams, 42);
        return page;
    }

    private void LoadPemFromDialog()
    {
        using var ofd = new OpenFileDialog { Filter = "PEM (*.pem;*.key;*.txt)|*.pem;*.key;*.txt|All files|*.*" };
        if (ofd.ShowDialog() != DialogResult.OK) return;
        LoadPemText(File.ReadAllText(ofd.FileName));
        ShowCurrent();
    }

    /// <summary>Nạp PEM. Nếu là private key thì suy ra luôn public key.</summary>
    private void LoadPemText(string text)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(text);          // tự nhận public/private
        bool isPrivate = text.Contains("PRIVATE KEY");
        if (isPrivate)
        {
            _privPem = text;
            _pubPem = rsa.ExportSubjectPublicKeyInfoPem();
        }
        else
        {
            _pubPem = text;
        }
        txtPubPem.Text = _pubPem;
        txtPrivPem.Text = _privPem ?? "";
        _lastLoaded = text;
        UpdateStatus();
    }

    private string _lastLoaded;

    private void ShowCurrent()
    {
        // Ưu tiên hiển thị file vừa nạp; nếu chưa có thì hiển thị private (hoặc public) đang dùng.
        string pem = _lastLoaded ?? _privPem ?? _pubPem;
        if (pem == null) throw new Exception("Chưa có khoá nào. Hãy sinh khoá hoặc nhập file PEM.");
        bool isPrivate = pem.Contains("PRIVATE KEY");

        txtPemView.Text = pem;
        var der = Asn1.PemToDer(pem, out var label);
        txtAsn1.Text = $"Nhãn: {label}   |   DER dài {der.Length} byte{Environment.NewLine}{Environment.NewLine}" +
                       Asn1.Dump(der) + Environment.NewLine +
                       "----- Hex dump DER -----" + Environment.NewLine + Asn1.HexDump(der);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var p = rsa.ExportParameters(isPrivate);
        var sb = new StringBuilder();
        sb.AppendLine($"Loại khoá: {(isPrivate ? "PRIVATE (chứa đủ n, e, d, p, q, dP, dQ, qInv)" : "PUBLIC (chỉ có n và e)")}   |   Độ dài khoá: {rsa.KeySize} bit");
        AppendNum(sb, "n (modulus)", p.Modulus);
        AppendNum(sb, "e (public exponent)", p.Exponent);
        if (isPrivate)
        {
            AppendNum(sb, "d (private exponent)", p.D);
            AppendNum(sb, "p", p.P);
            AppendNum(sb, "q", p.Q);
            AppendNum(sb, "dP = d mod (p-1)", p.DP);
            AppendNum(sb, "dQ = d mod (q-1)", p.DQ);
            AppendNum(sb, "qInv = q^-1 mod p", p.InverseQ);
        }
        txtParams.Text = sb.ToString();
    }

    private static void AppendNum(StringBuilder sb, string name, byte[] v)
    {
        if (v == null) return;
        var big = new BigInteger(v, isUnsigned: true, isBigEndian: true);
        sb.AppendLine();
        sb.AppendLine($"{name}: {big.GetBitLength()} bit, {v.Length} byte");
        sb.AppendLine("  hex: " + Convert.ToHexString(v));
        string dec = big.ToString();
        sb.AppendLine("  dec: " + (dec.Length > 300 ? dec[..300] + $"... ({dec.Length} chữ số)" : dec));
    }

    // =====================================================================
    //  Tab 3: Mã hoá / giải mã
    // =====================================================================
    private TabPage BuildCryptTab()
    {
        var page = new TabPage("5-6. Mã hoá & giải mã RSA");
        var t = Ui.Column(page);

        Ui.Auto(t, Ui.Bar(
            Btn("Nạp public PEM...", (_, _) => Guard(LoadPemFromDialogQuiet)),
            Btn("Nạp private PEM...", (_, _) => Guard(LoadPemFromDialogQuiet)),
            Ui.Label("(dùng khoá vừa sinh ở tab 1 hoặc nạp từ file)")));

        chkBase64 = new CheckBox { Text = "Dữ liệu nhập là Base64 của mảng byte (vd khoá AES 32 byte)", AutoSize = true };
        Ui.Auto(t, Ui.Bar(Ui.Label("Dữ liệu cần mã hoá (≤ 190 byte với khoá 2048 bit, OAEP-SHA256):"), chkBase64,
            Btn("Sinh khoá AES-256 mẫu (32 byte, Base64)", (_, _) =>
            {
                chkBase64.Checked = true;
                txtData.Text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            })));
        txtData = Ui.Text();
        txtData.WordWrap = true;
        txtData.Text = "Dữ liệu bí mật cần mã hoá bằng RSA";
        Ui.Fill(t, txtData, 20);

        lblLimit = Ui.Label("");
        Ui.Auto(t, Ui.Bar(Btn("Mã hoá bằng PUBLIC key → Base64", (_, _) => Guard(DoEncrypt)),
            Btn("Lưu bản mã ra file...", (_, _) => Guard(SaveCipher)), lblLimit));

        Ui.Auto(t, Ui.Label("Bản mã (Base64):"));
        txtCipherOut = Ui.Text();
        txtCipherOut.WordWrap = true;
        Ui.Fill(t, txtCipherOut, 25);

        txtCipherPath = new TextBox { Width = 460, ReadOnly = true };
        Ui.Auto(t, Ui.Bar(
            Btn("Chọn file bản mã (Base64)...", (_, _) => Guard(ChooseCipherFile)), txtCipherPath,
            Btn("Giải mã bằng PRIVATE key & so sánh", (_, _) => Guard(DoDecrypt))));

        Ui.Auto(t, Ui.Label("Kết quả giải mã và so sánh với dữ liệu gốc:"));
        txtDecryptOut = Ui.Text(true);
        txtDecryptOut.WordWrap = true;
        Ui.Fill(t, txtDecryptOut, 25);
        return page;
    }

    private void LoadPemFromDialogQuiet()
    {
        using var ofd = new OpenFileDialog { Filter = "PEM (*.pem;*.key;*.txt)|*.pem;*.key;*.txt|All files|*.*" };
        if (ofd.ShowDialog() != DialogResult.OK) return;
        LoadPemText(File.ReadAllText(ofd.FileName));
    }

    private byte[] GetInputBytes()
    {
        if (chkBase64.Checked) return Convert.FromBase64String(txtData.Text.Trim());
        return Encoding.UTF8.GetBytes(txtData.Text);
    }

    private void DoEncrypt()
    {
        using var rsa = Pub();
        int max = rsa.KeySize / 8 - 2 * 32 - 2;     // OAEP-SHA256: k - 2*hLen - 2
        var data = GetInputBytes();
        lblLimit.Text = $"Dữ liệu {data.Length} byte / tối đa {max} byte";
        if (data.Length > max)
            throw new Exception($"Dữ liệu {data.Length} byte vượt giới hạn {max} byte của khoá {rsa.KeySize} bit.");
        var cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        txtCipherOut.Text = Convert.ToBase64String(cipher);
    }

    private void SaveCipher()
    {
        if (string.IsNullOrWhiteSpace(txtCipherOut.Text)) throw new Exception("Chưa có bản mã.");
        using var sfd = new SaveFileDialog { Filter = "Text (*.txt)|*.txt|All files|*.*", FileName = "cipher_base64.txt" };
        if (sfd.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(sfd.FileName, txtCipherOut.Text.Trim());
        txtCipherPath.Text = sfd.FileName;
    }

    private void ChooseCipherFile()
    {
        using var ofd = new OpenFileDialog { Filter = "Text (*.txt)|*.txt|All files|*.*" };
        if (ofd.ShowDialog() != DialogResult.OK) return;
        txtCipherPath.Text = ofd.FileName;
    }

    private void DoDecrypt()
    {
        using var rsa = Priv();
        string b64 = !string.IsNullOrWhiteSpace(txtCipherPath.Text) && File.Exists(txtCipherPath.Text)
            ? File.ReadAllText(txtCipherPath.Text).Trim()
            : txtCipherOut.Text.Trim();
        if (b64.Length == 0) throw new Exception("Chưa có bản mã (chọn file hoặc mã hoá trước).");

        var plain = rsa.Decrypt(Convert.FromBase64String(b64), RSAEncryptionPadding.OaepSHA256);
        var original = GetInputBytes();
        bool same = plain.AsSpan().SequenceEqual(original);

        var sb = new StringBuilder();
        sb.AppendLine($"Giải mã được {plain.Length} byte.");
        sb.AppendLine("Dạng Base64: " + Convert.ToBase64String(plain));
        if (!chkBase64.Checked) sb.AppendLine("Dạng text  : " + Encoding.UTF8.GetString(plain));
        sb.AppendLine();
        sb.AppendLine($"Dữ liệu gốc: {original.Length} byte.");
        sb.AppendLine(same ? "=> KẾT QUẢ: GIỐNG HỆT dữ liệu gốc trước khi mã hoá." : "=> KẾT QUẢ: KHÁC dữ liệu gốc!");
        txtDecryptOut.Text = sb.ToString();
    }

    // =====================================================================
    //  Tab 4: Đánh giá tốc độ
    // =====================================================================
    private TabPage BuildBenchTab()
    {
        var page = new TabPage("7. Tốc độ mã hoá/giải mã");
        var t = Ui.Column(page);

        numIter = new NumericUpDown { Minimum = 10, Maximum = 100000, Value = 500, Width = 80 };
        Ui.Auto(t, Ui.Bar(Ui.Label("Số lần lặp:"), numIter,
            Btn("A. Đo với khoá đang dùng", async (_, _) => await RunBench(BenchCurrent)),
            Btn("B. So sánh các độ dài khoá 1024/2048/3072/4096", async (_, _) => await RunBench(BenchSizes))));

        var note = Ui.Text(true);
        note.WordWrap = true;
        note.Text = "Mã hoá bằng PUBLIC key dùng số mũ e nhỏ (thường 65537, chỉ 17 bit) nên nhanh. " +
                    "Giải mã/ký bằng PRIVATE key dùng số mũ d lớn (~ bằng n, hàng nghìn bit) nên chậm hơn nhiều " +
                    "(.NET dùng thêm CRT với p, q, dP, dQ, qInv để tăng tốc). Bấm nút để lấy số liệu thực tế trên máy của bạn.";
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
        note.Dock = DockStyle.Fill;
        t.Controls.Add(note);

        txtBench = Ui.Text(true);
        Ui.Fill(t, txtBench, 100);
        return page;
    }

    private record BenchResult(double EncMs, double DecMs, double SignMs, double VerifyMs);

    private static BenchResult Bench(RSA pub, RSA priv, int iters)
    {
        var data = RandomNumberGenerator.GetBytes(32);
        var enc = pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);   // khởi động (warm-up)
        priv.Decrypt(enc, RSAEncryptionPadding.OaepSHA256);
        var sig = priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        pub.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        double Time(Action a)
        {
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; i++) a();
            sw.Stop();
            return sw.Elapsed.TotalMilliseconds / iters;
        }

        double e = Time(() => pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
        double d = Time(() => priv.Decrypt(enc, RSAEncryptionPadding.OaepSHA256));
        double s = Time(() => priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        double v = Time(() => pub.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        return new BenchResult(e, d, s, v);
    }

    private async Task RunBench(Func<int, string, string, Task<string>> work)
    {
        int iters = (int)numIter.Value;
        string pubPem = _pubPem, privPem = _privPem;
        foreach (var b in _buttons) b.Enabled = false;
        UseWaitCursor = true;
        try { txtBench.Text = await work(iters, pubPem, privPem); }
        catch (Exception ex) { txtBench.Text = "LỖI: " + ex.Message; }
        finally { UseWaitCursor = false; foreach (var b in _buttons) b.Enabled = true; }
    }

    private Task<string> BenchCurrent(int iters, string pubPem, string privPem)
    {
        if (pubPem == null || privPem == null) throw new Exception("Cần có cả public và private key (sinh khoá ở tab 1 hoặc nạp private PEM).");
        return Task.Run(() =>
        {
            using var pub = RSA.Create(); pub.ImportFromPem(pubPem);
            using var priv = RSA.Create(); priv.ImportFromPem(privPem);
            var p = priv.ExportParameters(true);
            var e = new BigInteger(p.Exponent, true, true);
            var d = new BigInteger(p.D, true, true);
            var r = Bench(pub, priv, iters);
            var sb = new StringBuilder();
            sb.AppendLine($"Khoá {priv.KeySize} bit, {iters} lần lặp, dữ liệu 32 byte (OAEP-SHA256).");
            sb.AppendLine($"e = {e} ({e.GetBitLength()} bit)      d có {d.GetBitLength()} bit");
            sb.AppendLine();
            sb.AppendLine($"Mã hoá (public key, e nhỏ)       : {r.EncMs,9:F4} ms/lần");
            sb.AppendLine($"Giải mã (private key, d lớn)     : {r.DecMs,9:F4} ms/lần   → chậm hơn {r.DecMs / r.EncMs:F1} lần");
            sb.AppendLine($"Ký SHA256 (private key)          : {r.SignMs,9:F4} ms/lần");
            sb.AppendLine($"Xác thực chữ ký (public key)     : {r.VerifyMs,9:F4} ms/lần   → nhanh hơn ký {r.SignMs / r.VerifyMs:F1} lần");
            sb.AppendLine();
            sb.AppendLine("Kết luận: thao tác dùng private key (số mũ d lớn) tốn thời gian hơn rõ rệt so với thao tác dùng public key (e = 65537).");
            return sb.ToString();
        });
    }

    private Task<string> BenchSizes(int iters, string pubPem, string privPem)
    {
        int it = Math.Max(10, iters / 5);
        return Task.Run(() =>
        {
            var sb = new StringBuilder();
            sb.AppendLine($"So sánh theo độ dài khoá ({it} lần lặp mỗi thao tác).");
            sb.AppendLine("Độ dài | Sinh khoá (ms) | Mã hoá (ms) | Giải mã (ms) | Ký (ms) | Xác thực (ms) | Giải mã/Mã hoá");
            foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
            {
                var sw = Stopwatch.StartNew();
                using var priv = RSA.Create(bits);
                sw.Stop();
                using var pub = RSA.Create();
                pub.ImportSubjectPublicKeyInfo(priv.ExportSubjectPublicKeyInfo(), out _);
                var r = Bench(pub, priv, it);
                sb.AppendLine($"{bits,6} | {sw.Elapsed.TotalMilliseconds,14:F0} | {r.EncMs,11:F4} | {r.DecMs,12:F4} | {r.SignMs,7:F4} | {r.VerifyMs,13:F4} | {r.DecMs / r.EncMs,12:F1}x");
            }
            sb.AppendLine();
            sb.AppendLine("Nhận xét: khoá càng dài càng an toàn nhưng càng chậm; thời gian giải mã/ký tăng nhanh (xấp xỉ luỹ thừa 3 theo độ dài khoá), " +
                          "còn mã hoá/xác thực với e nhỏ tăng chậm hơn. Sinh khoá là bước tốn thời gian nhất vì phải tìm hai số nguyên tố lớn.");
            return sb.ToString();
        });
    }

    // =====================================================================
    //  Tab 5: SHA-256
    // =====================================================================
    private TabPage BuildHashTab()
    {
        var page = new TabPage("8. Băm SHA-256");
        var t = Ui.Column(page);

        Ui.Auto(t, Ui.Label("Nhập dữ liệu (băm tự cập nhật mỗi khi bạn gõ - thử đổi 1 ký tự):"));
        txtHashIn = Ui.Text();
        txtHashIn.WordWrap = true;
        txtHashIn.Text = "hello";
        txtHashIn.TextChanged += (_, _) => OnHashInputChanged();
        Ui.Fill(t, txtHashIn, 25);

        Ui.Auto(t, Ui.Bar(Ui.Label("SHA-256 (256 bit = 32 byte = 64 ký tự hex):"),
            Btn("Băm một file...", (_, _) => Guard(HashFile)),
            Btn("Xoá nhật ký", (_, _) => { txtHashLog.Clear(); _prevHash = null; OnHashInputChanged(); })));
        txtHashOut = Ui.Text(true);
        txtHashOut.WordWrap = true;
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        txtHashOut.Dock = DockStyle.Fill;
        t.Controls.Add(txtHashOut);

        Ui.Auto(t, Ui.Label("Nhật ký thay đổi (so sánh với lần băm trước - hiệu ứng tuyết lở):"));
        txtHashLog = Ui.Text(true);
        Ui.Fill(t, txtHashLog, 75);
        OnHashInputChanged();
        return page;
    }

    private void OnHashInputChanged()
    {
        if (txtHashLog == null || txtHashOut == null) return;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(txtHashIn.Text));
        txtHashOut.Text = Convert.ToHexString(hash);

        var sb = new StringBuilder();
        string shown = txtHashIn.Text.Length > 40 ? txtHashIn.Text[..40] + "..." : txtHashIn.Text;
        sb.AppendLine($"Đầu vào: \"{shown.Replace("\r", "").Replace("\n", "\\n")}\" ({txtHashIn.Text.Length} ký tự)");
        sb.AppendLine("SHA-256: " + Convert.ToHexString(hash));
        if (_prevHash != null)
        {
            int diffBits = 0;
            for (int i = 0; i < 32; i++) diffBits += BitOperations.PopCount((uint)(hash[i] ^ _prevHash[i]));
            int diffHex = 0;
            string a = Convert.ToHexString(hash), b = Convert.ToHexString(_prevHash);
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) diffHex++;
            sb.AppendLine($"So với lần trước: khác {diffBits}/256 bit ({diffBits / 2.56:F1}%), khác {diffHex}/64 ký tự hex ({diffHex / 0.64:F1}%)");
            sb.AppendLine("(Lý tưởng ≈ 50% số bit thay đổi dù đầu vào chỉ đổi rất ít)");
        }
        sb.AppendLine(new string('-', 70));
        txtHashLog.AppendText(sb.ToString());
        _prevHash = hash;
    }

    private void HashFile()
    {
        using var ofd = new OpenFileDialog { Filter = "All files|*.*" };
        if (ofd.ShowDialog() != DialogResult.OK) return;
        using var fs = File.OpenRead(ofd.FileName);
        var h = SHA256.HashData(fs);
        txtHashLog.AppendText($"File: {ofd.FileName}{Environment.NewLine}SHA-256: {Convert.ToHexString(h)}{Environment.NewLine}{new string('-', 70)}{Environment.NewLine}");
    }

    // =====================================================================
    //  Tab 6: Chữ ký số
    // =====================================================================
    private const string SignExplain =
@"CHỮ KÝ SỐ = RSA(private key) áp dụng lên giá trị băm SHA-256 của dữ liệu.
  - Dữ liệu khác nhau => băm khác nhau => chữ ký khác nhau (cùng người ký).
  - Với RSA PKCS#1 v1.5 (kiểu 'ký xác định'): cùng dữ liệu + cùng private key => chữ ký GIỐNG HỆT mỗi lần.

ĐỀ XUẤT ĐỂ CÙNG DỮ LIỆU + CÙNG NGƯỜI KÝ NHƯNG MỖI LẦN KÝ RA CHỮ KÝ KHÁC NHAU:
  Cách 1 (khuyên dùng): dùng RSASSA-PSS (chuẩn PKCS#1 v2.1 / RFC 8017). Trước khi ký, thêm một chuỗi muối (salt)
     NGẪU NHIÊN vào giá trị băm: M' = 0x00..00 || H(m) || salt, rồi H(M') được che (mask) bằng MGF1 và đóng gói
     thành khối EM; sau đó mới luỹ thừa bằng private key. Salt mới mỗi lần ký => EM khác => chữ ký khác.
     Salt được giấu sẵn trong chính chữ ký nên người xác thực tự khôi phục được; không cần gửi thêm gì, và
     chữ ký vẫn xác thực đúng với cùng public key. (Trong .NET: RSASignaturePadding.Pss)
  Cách 2: ghép thêm nonce ngẫu nhiên/dấu thời gian vào dữ liệu trước khi băm:  sig = Sign( H(m || nonce) ),
     rồi gửi kèm (m, nonce, sig). Mỗi lần ký nonce khác => chữ ký khác; nhược điểm là phải truyền thêm nonce.
  Cách 3: dùng 'randomized hashing' (RFC 6979 đảo ngược: ngẫu nhiên hoá thông điệp trước khi băm) - tương tự cách 2.
  Lợi ích của việc ngẫu nhiên hoá: chống tấn công đoán/so khớp chữ ký, chống suy diễn thông tin từ việc chữ ký lặp lại,
  và PSS có chứng minh an toàn chặt chẽ hơn PKCS#1 v1.5.";

    private TabPage BuildSignTab()
    {
        var page = new TabPage("9. Chữ ký số");
        var t = Ui.Column(page);

        var explain = Ui.Text(true);
        explain.WordWrap = true;
        explain.Text = SignExplain.Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 250));
        explain.Dock = DockStyle.Fill;
        t.Controls.Add(explain);

        Ui.Auto(t, Ui.Label("Dữ liệu cần ký (dùng PRIVATE key đang nạp):"));
        txtSignData = Ui.Text();
        txtSignData.WordWrap = true;
        txtSignData.Text = "Hợp đồng số 01/2026: Bên A đồng ý chuyển cho Bên B 100.000.000 đồng.";
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
        txtSignData.Dock = DockStyle.Fill;
        t.Controls.Add(txtSignData);

        Ui.Auto(t, Ui.Bar(
            Btn("Ký 3 lần: PKCS#1 v1.5 (xác định)", (_, _) => Guard(() => SignRepeat(RSASignaturePadding.Pkcs1, "PKCS#1 v1.5"))),
            Btn("Ký 3 lần: PSS (ngẫu nhiên hoá)", (_, _) => Guard(() => SignRepeat(RSASignaturePadding.Pss, "RSASSA-PSS"))),
            Btn("Ký dữ liệu gốc & dữ liệu đổi 1 ký tự", (_, _) => Guard(SignTwoData))));

        txtSignOut = Ui.Text(true);
        Ui.Fill(t, txtSignOut, 100);
        return page;
    }

    private static string Brief(byte[] sig)
    {
        string b = Convert.ToBase64String(sig);
        return b.Length > 64 ? b[..32] + " ... " + b[^32..] : b;
    }

    private void SignRepeat(RSASignaturePadding padding, string name)
    {
        using var priv = Priv();
        using var pub = Pub();
        var data = Encoding.UTF8.GetBytes(txtSignData.Text);
        var sigs = new List<byte[]>();
        var sb = new StringBuilder();
        sb.AppendLine($"=== Ký cùng một dữ liệu 3 lần, cùng private key, kiểu {name} ===");
        for (int i = 1; i <= 3; i++)
        {
            var sig = priv.SignData(data, HashAlgorithmName.SHA256, padding);
            bool ok = pub.VerifyData(data, sig, HashAlgorithmName.SHA256, padding);
            sigs.Add(sig);
            sb.AppendLine($"Lần {i}: {Brief(sig)}   [xác thực bằng public key: {(ok ? "HỢP LỆ" : "KHÔNG hợp lệ")}]");
        }
        bool allSame = sigs[0].AsSpan().SequenceEqual(sigs[1]) && sigs[1].AsSpan().SequenceEqual(sigs[2]);
        bool allDiff = !sigs[0].AsSpan().SequenceEqual(sigs[1]) && !sigs[1].AsSpan().SequenceEqual(sigs[2]) && !sigs[0].AsSpan().SequenceEqual(sigs[2]);
        sb.AppendLine(allSame ? "=> 3 chữ ký GIỐNG HỆT nhau (ký xác định)."
                     : allDiff ? "=> 3 chữ ký KHÁC NHAU hoàn toàn, nhưng đều xác thực đúng → đạt mong muốn của đề bài."
                     : "=> Có chữ ký trùng, có chữ ký khác.");
        sb.AppendLine();
        txtSignOut.AppendText(sb.ToString());
    }

    private void SignTwoData()
    {
        using var priv = Priv();
        using var pub = Pub();
        var d1 = Encoding.UTF8.GetBytes(txtSignData.Text);
        var d2 = Encoding.UTF8.GetBytes(txtSignData.Text + ".");
        var s1 = priv.SignData(d1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var s2 = priv.SignData(d2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sb = new StringBuilder();
        sb.AppendLine("=== Dữ liệu khác nhau (thêm 1 dấu chấm) → chữ ký khác nhau (PKCS#1 v1.5) ===");
        sb.AppendLine("SHA-256 gốc : " + Convert.ToHexString(SHA256.HashData(d1)));
        sb.AppendLine("SHA-256 đổi : " + Convert.ToHexString(SHA256.HashData(d2)));
        sb.AppendLine("Chữ ký gốc   : " + Brief(s1));
        sb.AppendLine("Chữ ký đổi    : " + Brief(s2));
        sb.AppendLine("Hai chữ ký " + (s1.AsSpan().SequenceEqual(s2) ? "GIỐNG nhau." : "KHÁC nhau."));
        sb.AppendLine("Dùng chữ ký của dữ liệu gốc để xác thực dữ liệu đã đổi: " +
                      (pub.VerifyData(d2, s1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) ? "HỢP LỆ (bất thường!)" : "KHÔNG hợp lệ → phát hiện dữ liệu bị sửa."));
        sb.AppendLine();
        txtSignOut.AppendText(sb.ToString());
    }
}

/// <summary>Các hàm dựng giao diện nhỏ gọn.</summary>
internal static class Ui
{
    public static TableLayoutPanel Column(Control parent)
    {
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(8) };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        parent.Controls.Add(t);
        return t;
    }

    public static void Auto(TableLayoutPanel t, Control c)
    {
        c.Dock = DockStyle.Fill;
        t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        t.Controls.Add(c);
    }

    public static void Fill(TableLayoutPanel t, Control c, float percent = 100)
    {
        c.Dock = DockStyle.Fill;
        t.RowStyles.Add(new RowStyle(SizeType.Percent, percent));
        t.Controls.Add(c);
    }

    public static FlowLayoutPanel Bar(params Control[] controls)
    {
        var f = new FlowLayoutPanel { AutoSize = true, WrapContents = true };
        f.Controls.AddRange(controls);
        return f;
    }

    public static Label Label(string text) =>
        new Label { Text = text, AutoSize = true, Padding = new Padding(0, 6, 4, 0) };

    public static Button Button(string text, EventHandler onClick)
    {
        var b = new Button { Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(6, 2, 6, 2) };
        b.Click += onClick;
        return b;
    }

    public static TextBox Text(bool readOnly = false) => new TextBox
    {
        Multiline = true,
        ScrollBars = ScrollBars.Both,
        WordWrap = false,
        ReadOnly = readOnly,
        Font = new Font("Consolas", 10f),
    };
}
