using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Bai1_AES;

/// <summary>
/// Bài 1 - Mã hoá đối xứng AES (WinForms).
/// Chức năng: sinh khoá, lưu/nhập khoá, mã hoá văn bản, mã hoá/giải mã file lớn,
/// đo thời gian, so sánh file nguồn với file giải mã theo từng byte.
/// </summary>
public class MainForm : Form
{
    // ---------- Trạng thái ----------
    private byte[] _key;                                   // khoá AES hiện tại
    private readonly List<TestResult> _results = new();    // lưu số liệu để rút ra kết luận

    private record TestResult(long Bytes, double EncSec, double DecSec, bool Same);

    // ---------- Điều khiển ----------
    private ComboBox cboKeySize;
    private TextBox txtKey, txtPlain, txtCipher, txtSrc, txtEnc, txtDec, txtLog;
    private Label lblKeyInfo;
    private NumericUpDown numSizeMb;
    private ProgressBar bar;
    private readonly List<Button> _buttons = new();

    public MainForm()
    {
        Text = "Bài 1 - Mã hoá AES";
        Width = 980;
        Height = 760;
        StartPosition = FormStartPosition.CenterScreen;

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildKeyTab());
        tabs.TabPages.Add(BuildTextTab());
        tabs.TabPages.Add(BuildFileTab());
        Controls.Add(tabs);
    }

    // =====================================================================
    //  Giao diện
    // =====================================================================
    private TabPage BuildKeyTab()
    {
        var page = new TabPage("1-3. Khoá AES");
        var t = Ui.Column(page);

        cboKeySize = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
        cboKeySize.Items.AddRange(new object[] { "128", "192", "256" });
        cboKeySize.SelectedItem = "256";

        Ui.Auto(t, Ui.Bar(Ui.Label("Độ dài khoá (bit):"), cboKeySize,
            Btn("Sinh khoá AES", (_, _) => GenerateKey()),
            Btn("Lưu khoá ra file...", (_, _) => SaveKey()),
            Btn("Nạp khoá từ file...", (_, _) => LoadKey())));

        lblKeyInfo = Ui.Label("Chưa có khoá.");
        Ui.Auto(t, lblKeyInfo);

        Ui.Auto(t, Ui.Label("Khoá hiện tại (Base64):"));
        txtKey = Ui.Text(readOnly: true);
        txtKey.WordWrap = true;
        Ui.Fill(t, txtKey, 30);

        Ui.Auto(t, Ui.Label("Khoá hiện tại (Hex):"));
        var txtHex = Ui.Text(readOnly: true);
        txtHex.WordWrap = true;
        txtHex.Name = "txtKeyHex";
        Ui.Fill(t, txtHex, 30);
        return page;
    }

    private TabPage BuildTextTab()
    {
        var page = new TabPage("4. Mã hoá văn bản");
        var t = Ui.Column(page);

        Ui.Auto(t, Ui.Label("Văn bản cần mã hoá:"));
        txtPlain = Ui.Text();
        txtPlain.WordWrap = true;
        txtPlain.Text = "Xin chào, đây là đoạn văn bản thử nghiệm mã hoá AES.";
        Ui.Fill(t, txtPlain, 40);

        Ui.Auto(t, Ui.Bar(
            Btn("Mã hoá  ↓", (_, _) => EncryptText()),
            Btn("Giải mã (từ ô bên dưới)  ↑", (_, _) => DecryptText())));

        Ui.Auto(t, Ui.Label("Kết quả mã hoá = Base64( IV[16 byte] + bản mã ):"));
        txtCipher = Ui.Text();
        txtCipher.WordWrap = true;
        Ui.Fill(t, txtCipher, 60);
        return page;
    }

    private TabPage BuildFileTab()
    {
        var page = new TabPage("5. Mã hoá file / Thử nghiệm file lớn");
        var t = Ui.Column(page);

        txtSrc = new TextBox { Width = 560 };
        txtEnc = new TextBox { Width = 560, ReadOnly = true };
        txtDec = new TextBox { Width = 560, ReadOnly = true };

        Ui.Auto(t, Ui.Bar(Ui.Label("File nguồn:     "), txtSrc,
            Btn("Chọn file...", (_, _) => ChooseSource())));
        Ui.Auto(t, Ui.Bar(Ui.Label("File đã mã hoá:"), txtEnc));
        Ui.Auto(t, Ui.Bar(Ui.Label("File giải mã:    "), txtDec));

        numSizeMb = new NumericUpDown { Minimum = 1, Maximum = 200000, Value = 1024, Width = 90 };
        Ui.Auto(t, Ui.Bar(Ui.Label("Tạo file thử (MB):"), numSizeMb,
            Btn("Tạo file ngẫu nhiên...", async (_, _) => await MakeTestFileAsync()),
            Ui.Label("(1024 MB = 1 GB; cần ~3 lần dung lượng này: nguồn + mã hoá + giải mã)")));

        Ui.Auto(t, Ui.Bar(
            Btn("Mã hoá file", async (_, _) => await RunBusy(EncryptFileStepAsync)),
            Btn("Giải mã file", async (_, _) => await RunBusy(DecryptFileStepAsync)),
            Btn("So sánh byte nguồn ↔ giải mã", async (_, _) => await RunBusy(CompareStepAsync)),
            Btn("Chạy toàn bộ (mã hoá → giải mã → so sánh)", async (_, _) => await RunBusy(FullTestAsync)),
            Btn("Kết luận từ số liệu", (_, _) => Conclude())));

        bar = new ProgressBar { Dock = DockStyle.Fill, Height = 18 };
        Ui.Auto(t, bar);

        txtLog = Ui.Text(readOnly: true);
        Ui.Fill(t, txtLog, 100);
        return page;
    }

    private Button Btn(string text, EventHandler h)
    {
        var b = Ui.Button(text, h);
        _buttons.Add(b);
        return b;
    }

    private void SetBusy(bool busy)
    {
        foreach (var b in _buttons) b.Enabled = !busy;
        UseWaitCursor = busy;
    }

    private void Log(string s)
    {
        if (InvokeRequired) { Invoke((Action)(() => Log(s))); return; }
        txtLog.AppendText(s + Environment.NewLine);
    }

    // =====================================================================
    //  1-3. Khoá
    // =====================================================================
    private void ShowKey()
    {
        txtKey.Text = Convert.ToBase64String(_key);
        var hex = Controls.Find("txtKeyHex", true).FirstOrDefault() as TextBox;
        if (hex != null) hex.Text = Convert.ToHexString(_key);
        lblKeyInfo.Text = $"Khoá AES-{_key.Length * 8} bit ({_key.Length} byte).";
    }

    private void GenerateKey()
    {
        int bits = int.Parse((string)cboKeySize.SelectedItem);
        _key = new byte[bits / 8];
        RandomNumberGenerator.Fill(_key);       // sinh khoá bằng bộ sinh số ngẫu nhiên mật mã
        ShowKey();
    }

    private void SaveKey()
    {
        if (_key == null) { MessageBox.Show("Chưa có khoá. Hãy sinh khoá trước."); return; }
        using var sfd = new SaveFileDialog { Filter = "AES key (*.key)|*.key|All files|*.*", FileName = "aes.key" };
        if (sfd.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(sfd.FileName, Convert.ToBase64String(_key));   // lưu dạng Base64 text
        MessageBox.Show("Đã lưu khoá:\n" + sfd.FileName);
    }

    private void LoadKey()
    {
        using var ofd = new OpenFileDialog { Filter = "AES key (*.key)|*.key|All files|*.*" };
        if (ofd.ShowDialog() != DialogResult.OK) return;
        try
        {
            var k = Convert.FromBase64String(File.ReadAllText(ofd.FileName).Trim());
            if (k.Length != 16 && k.Length != 24 && k.Length != 32)
                throw new Exception($"Độ dài khoá {k.Length} byte không hợp lệ (cần 16, 24 hoặc 32).");
            _key = k;
            cboKeySize.SelectedItem = (k.Length * 8).ToString();
            ShowKey();
        }
        catch (Exception ex) { MessageBox.Show("Không nạp được khoá: " + ex.Message); }
    }

    private bool RequireKey()
    {
        if (_key != null) return true;
        MessageBox.Show("Chưa có khoá AES. Hãy sinh khoá hoặc nạp khoá từ file ở tab đầu tiên.");
        return false;
    }

    // =====================================================================
    //  4. Văn bản
    // =====================================================================
    private void EncryptText()
    {
        if (!RequireKey()) return;
        try
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.GenerateIV();                                   // IV ngẫu nhiên mỗi lần mã hoá
            var data = Encoding.UTF8.GetBytes(txtPlain.Text);
            var cipher = aes.EncryptCbc(data, aes.IV);          // CBC + PKCS7
            var all = new byte[16 + cipher.Length];
            Buffer.BlockCopy(aes.IV, 0, all, 0, 16);
            Buffer.BlockCopy(cipher, 0, all, 16, cipher.Length);
            txtCipher.Text = Convert.ToBase64String(all);
        }
        catch (Exception ex) { MessageBox.Show("Lỗi mã hoá: " + ex.Message); }
    }

    private void DecryptText()
    {
        if (!RequireKey()) return;
        try
        {
            var all = Convert.FromBase64String(txtCipher.Text.Trim());
            if (all.Length < 32) throw new Exception("Dữ liệu quá ngắn.");
            var iv = all[..16];
            var cipher = all[16..];
            using var aes = Aes.Create();
            aes.Key = _key;
            var plain = aes.DecryptCbc(cipher, iv);
            txtPlain.Text = Encoding.UTF8.GetString(plain);
        }
        catch (Exception ex) { MessageBox.Show("Lỗi giải mã (sai khoá hoặc dữ liệu hỏng): " + ex.Message); }
    }

    // =====================================================================
    //  5. File
    // =====================================================================
    private void ChooseSource()
    {
        using var ofd = new OpenFileDialog { Filter = "All files|*.*" };
        if (ofd.ShowDialog() != DialogResult.OK) return;
        SetSource(ofd.FileName);
    }

    private void SetSource(string path)
    {
        txtSrc.Text = path;
        txtEnc.Text = path + ".enc";
        txtDec.Text = path + ".dec";
    }

    private async Task MakeTestFileAsync()
    {
        using var sfd = new SaveFileDialog { Filter = "Binary (*.bin)|*.bin", FileName = "test_data.bin" };
        if (sfd.ShowDialog() != DialogResult.OK) return;
        long bytes = (long)numSizeMb.Value * 1024 * 1024;
        string path = sfd.FileName;
        var prog = new Progress<int>(v => bar.Value = Math.Clamp(v, 0, 100));
        await RunBusy(async () =>
        {
            Log($"Đang tạo file ngẫu nhiên {numSizeMb.Value} MB: {path}");
            var sw = Stopwatch.StartNew();
            await Task.Run(() => MakeRandomFile(path, bytes, prog));
            Log($"Tạo xong sau {sw.Elapsed.TotalSeconds:F2} giây.");
            SetSource(path);
        });
    }

    private static void MakeRandomFile(string path, long bytes, IProgress<int> progress)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        var buf = new byte[4 << 20];
        long written = 0;
        while (written < bytes)
        {
            RandomNumberGenerator.Fill(buf);
            int n = (int)Math.Min(buf.Length, bytes - written);
            fs.Write(buf, 0, n);
            written += n;
            progress.Report((int)(written * 100 / bytes));
        }
    }

    private async Task RunBusy(Func<Task> work)
    {
        SetBusy(true);
        try { await work(); }
        catch (Exception ex) { Log("LỖI: " + ex.Message); }
        finally { SetBusy(false); bar.Value = 0; }
    }

    private bool CheckPaths()
    {
        if (!RequireKey()) return false;
        if (string.IsNullOrWhiteSpace(txtSrc.Text) || !File.Exists(txtSrc.Text))
        {
            MessageBox.Show("Hãy chọn file nguồn (hoặc tạo file thử) trước.");
            return false;
        }
        return true;
    }

    private IProgress<int> NewProgress() => new Progress<int>(v => bar.Value = Math.Clamp(v, 0, 100));

    // ----- Mã hoá file -----
    private async Task<double> EncryptFileStepAsync()
    {
        if (!CheckPaths()) return -1;
        string src = txtSrc.Text, dst = txtEnc.Text;
        var key = _key;
        var prog = NewProgress();
        Log($"[Mã hoá] {src}");
        var sw = Stopwatch.StartNew();
        await Task.Run(() => EncryptFile(key, src, dst, prog));
        sw.Stop();
        long size = new FileInfo(src).Length;
        Log($"[Mã hoá] xong: {size:N0} byte trong {sw.Elapsed.TotalSeconds:F3} giây  " +
            $"({size / 1048576.0 / sw.Elapsed.TotalSeconds:F1} MB/s). File ra: {new FileInfo(dst).Length:N0} byte");
        return sw.Elapsed.TotalSeconds;
    }

    private async Task<double> DecryptFileStepAsync()
    {
        if (!CheckPaths()) return -1;
        if (!File.Exists(txtEnc.Text)) { MessageBox.Show("Chưa có file mã hoá."); return -1; }
        string src = txtEnc.Text, dst = txtDec.Text;
        var key = _key;
        var prog = NewProgress();
        Log($"[Giải mã] {src}");
        var sw = Stopwatch.StartNew();
        await Task.Run(() => DecryptFile(key, src, dst, prog));
        sw.Stop();
        long size = new FileInfo(dst).Length;
        Log($"[Giải mã] xong: {size:N0} byte trong {sw.Elapsed.TotalSeconds:F3} giây  " +
            $"({size / 1048576.0 / sw.Elapsed.TotalSeconds:F1} MB/s)");
        return sw.Elapsed.TotalSeconds;
    }

    private async Task<bool> CompareStepAsync()
    {
        if (!CheckPaths()) return false;
        if (!File.Exists(txtDec.Text)) { MessageBox.Show("Chưa có file giải mã."); return false; }
        string a = txtSrc.Text, b = txtDec.Text;
        var prog = NewProgress();
        Log($"[So sánh byte] {Path.GetFileName(a)} ↔ {Path.GetFileName(b)}");
        var sw = Stopwatch.StartNew();
        var (same, firstDiff) = await Task.Run(() => CompareFiles(a, b, prog));
        sw.Stop();
        Log(same
            ? $"[So sánh byte] GIỐNG NHAU hoàn toàn từng byte ({sw.Elapsed.TotalSeconds:F2} giây)."
            : $"[So sánh byte] KHÁC NHAU, byte khác đầu tiên tại offset {firstDiff:N0}.");
        return same;
    }

    private async Task FullTestAsync()
    {
        if (!CheckPaths()) return;
        long size = new FileInfo(txtSrc.Text).Length;
        Log($"===== Thử nghiệm đầy đủ, file {size / 1048576.0:F1} MB, khoá AES-{_key.Length * 8} =====");
        double enc = await EncryptFileStepAsync();
        if (enc < 0) return;
        double dec = await DecryptFileStepAsync();
        if (dec < 0) return;
        bool same = await CompareStepAsync();
        _results.Add(new TestResult(size, enc, dec, same));
        Log("===== Kết thúc =====");
    }

    // ----- Lõi mã hoá file (streaming, bộ đệm 1 MB nên file hàng GB vẫn chạy được) -----
    private const int BufSize = 1 << 20;

    private static void EncryptFile(byte[] key, string src, string dst, IProgress<int> progress)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        fout.Write(aes.IV, 0, 16);                                   // ghi IV ở đầu file
        using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
        Pump(fin, cs, fin.Length, progress);
    }

    private static void DecryptFile(byte[] key, string src, string dst, IProgress<int> progress)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        var iv = new byte[16];
        ReadFully(fin, iv, 16);
        aes.IV = iv;
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
        Pump(cs, fout, fin.Length, progress, useInnerPosition: fin);
    }

    private static void Pump(Stream from, Stream to, long total, IProgress<int> progress, FileStream useInnerPosition = null)
    {
        var buf = new byte[BufSize];
        int n, lastPct = -1;
        while ((n = from.Read(buf, 0, buf.Length)) > 0)
        {
            to.Write(buf, 0, n);
            long pos = useInnerPosition != null ? useInnerPosition.Position : from.Position;
            int pct = total > 0 ? (int)(pos * 100 / total) : 0;
            if (pct != lastPct) { progress.Report(pct); lastPct = pct; }
        }
    }

    private static int ReadFully(Stream s, byte[] buf, int count)
    {
        int total = 0;
        while (total < count)
        {
            int n = s.Read(buf, total, count - total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    private static (bool Same, long FirstDiff) CompareFiles(string a, string b, IProgress<int> progress)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        if (fa.Length != fb.Length) return (false, Math.Min(fa.Length, fb.Length));
        var ba = new byte[BufSize];
        var bb = new byte[BufSize];
        long offset = 0;
        int lastPct = -1;
        while (offset < fa.Length)
        {
            int na = ReadFully(fa, ba, ba.Length);
            int nb = ReadFully(fb, bb, bb.Length);
            if (na != nb) return (false, offset);
            if (na == 0) break;
            if (!ba.AsSpan(0, na).SequenceEqual(bb.AsSpan(0, nb)))
            {
                for (int i = 0; i < na; i++)
                    if (ba[i] != bb[i]) return (false, offset + i);
            }
            offset += na;
            int pct = (int)(offset * 100 / fa.Length);
            if (pct != lastPct) { progress.Report(pct); lastPct = pct; }
        }
        return (true, -1);
    }

    // =====================================================================
    //  Kết luận dựa trên số liệu
    // =====================================================================
    private void Conclude()
    {
        if (_results.Count == 0)
        {
            MessageBox.Show("Chưa có số liệu. Hãy chạy 'Chạy toàn bộ' ít nhất một lần (nên thử vài kích thước khác nhau).");
            return;
        }
        var sb = new StringBuilder();
        sb.AppendLine("===== BẢNG SỐ LIỆU =====");
        sb.AppendLine("Kích thước (MB) | Mã hoá (s) | Giải mã (s) | Mã hoá MB/s | Giải mã MB/s | Byte giống nhau");
        foreach (var r in _results.OrderBy(x => x.Bytes))
        {
            double mb = r.Bytes / 1048576.0;
            sb.AppendLine($"{mb,14:F1} | {r.EncSec,10:F2} | {r.DecSec,11:F2} | {mb / r.EncSec,11:F1} | {mb / r.DecSec,12:F1} | {(r.Same ? "CÓ" : "KHÔNG")}");
        }
        double avgEnc = _results.Average(r => r.Bytes / 1048576.0 / r.EncSec);
        double avgDec = _results.Average(r => r.Bytes / 1048576.0 / r.DecSec);
        sb.AppendLine();
        sb.AppendLine("===== KẾT LUẬN (rút ra từ số liệu trên) =====");
        sb.AppendLine($"1. Tốc độ trung bình: mã hoá ≈ {avgEnc:F1} MB/s, giải mã ≈ {avgDec:F1} MB/s.");
        sb.AppendLine(avgDec > avgEnc * 1.1
            ? "2. Giải mã nhanh hơn mã hoá một chút (CBC giải mã có thể xử lý song song các khối, mã hoá thì tuần tự)."
            : avgEnc > avgDec * 1.1
                ? "2. Mã hoá nhanh hơn giải mã trong lần đo này."
                : "2. Thời gian mã hoá và giải mã xấp xỉ nhau.");
        if (_results.Count >= 2)
        {
            var o = _results.OrderBy(x => x.Bytes).ToList();
            double ratioSize = (double)o[^1].Bytes / o[0].Bytes;
            double ratioTime = o[^1].EncSec / o[0].EncSec;
            sb.AppendLine($"3. Kích thước tăng {ratioSize:F1} lần thì thời gian mã hoá tăng {ratioTime:F1} lần → thời gian tăng gần tuyến tính theo kích thước (độ phức tạp O(n)).");
        }
        else
        {
            sb.AppendLine("3. Hãy thử thêm file kích thước khác (ví dụ 100 MB, 1 GB, 3 GB) để so sánh sự tăng thời gian theo kích thước.");
        }
        sb.AppendLine(_results.All(r => r.Same)
            ? "4. Mọi lần thử: file giải mã trùng khớp từng byte với file nguồn → thuật toán đúng, không mất dữ liệu."
            : "4. CÓ lần thử file giải mã KHÁC file nguồn → cần kiểm tra lại khoá/quy trình.");
        sb.AppendLine("5. AES là mã hoá đối xứng: dùng chung một khoá để mã hoá và giải mã, rất nhanh nên phù hợp mã hoá dữ liệu lớn; vấn đề khó là bảo vệ và trao đổi khoá an toàn (giải quyết bằng RSA ở Bài 2).");
        sb.AppendLine("6. Bộ nhớ sử dụng không đổi (đệm 1 MB) dù file lớn đến đâu vì xử lý theo luồng (stream); tốc độ thực tế còn phụ thuộc ổ đĩa (HDD/SSD) và việc CPU có hỗ trợ AES-NI.");
        Log(sb.ToString());
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
