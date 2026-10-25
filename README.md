# Các bước tự làm bài tập AES & RSA (C# WinForms), có giải thích chi tiết

Tài liệu hướng dẫn **tự tạo project và viết code từng bước** trong Visual Studio. Mỗi bước gồm:
- **Mục đích:** bước này làm gì và vì sao cần.
- **Code:** đoạn mã để dán vào.
- **Giải thích:** từng dòng/ý chính, để bạn hiểu và trả lời được khi thầy cô hỏi.

(Code hoàn chỉnh để đối chiếu nằm trong thư mục `Bai1_AES` và `Bai2_RSA`.)

---

## PHẦN 0. KIẾN THỨC NỀN CẦN HIỂU TRƯỚC

### 0.1. Mã hoá đối xứng và bất đối xứng
| | Đối xứng (AES) | Bất đối xứng (RSA) |
|---|---|---|
| Khoá | 1 khoá dùng chung để mã hoá và giải mã | Cặp khoá: public (công khai) và private (bí mật) |
| Tốc độ | Rất nhanh | Chậm hơn nhiều |
| Dữ liệu | Mã hoá được dữ liệu lớn (GB) | Chỉ mã hoá dữ liệu rất nhỏ (< ~190 byte) |
| Khó khăn | Làm sao trao đổi khoá an toàn? | Không phải trao đổi bí mật |
| Dùng thực tế | Mã hoá nội dung file/tin nhắn | Mã hoá khoá AES, chữ ký số |

Thực tế hai loại thường kết hợp: dùng AES mã hoá dữ liệu, rồi dùng RSA mã hoá khoá AES. Đó chính là lý do đề Bài 2 yêu cầu mã hoá mảng byte ≤ 190 byte (khoá AES 256 bit = 32 byte).

### 0.2. Các khái niệm AES dùng trong bài
- **Khoá:** 128/192/256 bit (16/24/32 byte). Khoá càng dài càng an toàn, tốc độ chỉ chậm hơn chút.
- **Khối (block):** AES luôn xử lý từng khối 16 byte.
- **Chế độ CBC:** mỗi khối rõ được XOR với khối mã trước đó rồi mới mã hoá, nên cùng nội dung ở hai vị trí cho bản mã khác nhau. Khối đầu tiên cần một giá trị khởi đầu gọi là **IV**.
- **IV (Initialization Vector):** 16 byte ngẫu nhiên, **không cần bí mật** nhưng phải **khác nhau mỗi lần mã hoá** và cần có khi giải mã. Vì vậy ta ghi IV ở đầu bản mã.
- **Padding (PKCS7):** dữ liệu không chia hết 16 byte thì được đệm thêm cho đủ khối cuối. Do đó bản mã luôn dài hơn bản rõ từ 1 đến 16 byte.

### 0.3. Các khái niệm RSA dùng trong bài
- Chọn hai số nguyên tố lớn **p, q**. Tính **n = p·q** (modulus). Public key là cặp **(n, e)**, private key là **(n, d)** (cùng p, q, dP, dQ, qInv để tăng tốc).
- Mã hoá: `c = m^e mod n`. Giải mã: `m = c^d mod n`.
- **e thường là 65537** (chỉ 17 bit) nên mã hoá nhanh; **d lớn bằng cỡ n** (2048 bit) nên giải mã chậm. Đây chính là nội dung câu 7 của đề.
- **Padding OAEP:** RSA "thuần" không an toàn, nên phải thêm đệm ngẫu nhiên OAEP. Với SHA-256 và khoá 2048 bit, dữ liệu tối đa = 256 − 2×32 − 2 = **190 byte**. Dữ liệu dài hơn mức này thì không mã hoá được.
- **Chữ ký số:** dùng private key "mã hoá" giá trị băm của dữ liệu; ai có public key đều kiểm tra được.
- **PEM:** định dạng văn bản của khoá (Base64 của dữ liệu nhị phân DER kèm dòng BEGIN/END).

---

## PHẦN 1. TẠO PROJECT

**Mục đích:** có khung ứng dụng cửa sổ (Windows Forms) để đặt nút bấm, ô nhập.

1. Mở Visual Studio → **Create a new project**.
2. Chọn **Windows Forms App** (C#, loại .NET, không chọn ".NET Framework") → Next.
3. Đặt tên `Bai1_AES`, chọn vị trí lưu trên ổ D → Next → chọn framework mới nhất → **Create**.
4. Làm tương tự cho Bài 2 với tên `Bai2_RSA` (mỗi bài một project riêng).
5. Ở đầu file `Form1.cs`, thêm các thư viện:

```csharp
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
```

**Giải thích các `using`:**
- `System.Security.Cryptography`: chứa `Aes`, `RSA`, `SHA256`, `RandomNumberGenerator`.
- `System.Diagnostics`: chứa `Stopwatch` để đo thời gian.
- `System.Text`: chứa `Encoding.UTF8` để đổi chuỗi sang mảng byte và ngược lại.

6. **Cách thêm điều khiển:** mở `Form1.cs [Design]`, kéo điều khiển từ **Toolbox** (View → Toolbox) vào form. Bấm đúp vào Button để tạo hàm `Click`. Đặt tên điều khiển trong **Properties → (Name)**.

**Vì sao phải đặt tên điều khiển?** Code truy cập điều khiển qua tên (ví dụ `txtKey.Text`). Tên sai thì code báo lỗi đỏ.

---

## PHẦN 2. BÀI 1: MÃ HOÁ AES

### Bước 1. Thiết kế giao diện

**Mục đích:** có chỗ nhập liệu và nút cho từng yêu cầu của đề.

| Điều khiển | (Name) | Ghi chú |
|---|---|---|
| ComboBox | `cboKeySize` | Items: 128, 192, 256 (bấm mũi tên nhỏ → Edit Items) |
| Button | `btnGenKey` | "Sinh khoá" |
| Button | `btnSaveKey` | "Lưu khoá" |
| Button | `btnLoadKey` | "Nạp khoá" |
| TextBox | `txtKey` | Multiline, hiện khoá Base64 |
| TextBox | `txtPlain` | Multiline, văn bản gốc |
| Button | `btnEncText`, `btnDecText` | "Mã hoá", "Giải mã" |
| TextBox | `txtCipher` | Multiline, bản mã Base64 |
| TextBox | `txtSrc` | Đường dẫn file nguồn |
| Button | `btnBrowse`, `btnMakeFile`, `btnEncFile`, `btnDecFile`, `btnCompare` | Chọn file, tạo file thử, mã hoá, giải mã, so sánh |
| NumericUpDown | `numMb` | Kích thước file thử (MB), đặt Maximum = 100000 |
| TextBox | `txtLog` | Multiline, ScrollBars=Vertical, ReadOnly |

**Giải thích:** `Multiline` cho phép ô nhập nhiều dòng (bản mã Base64 rất dài). `ReadOnly` cho ô log để không gõ nhầm vào đó.

### Bước 2. Khai báo biến khoá và hàm ghi log

**Mục đích:** các nút bấm phải dùng chung một khoá, nên khoá được lưu trong biến của form.

```csharp
byte[] key;                       // khoá AES hiện tại

void Log(string s) => txtLog.AppendText(s + Environment.NewLine);
```

**Giải thích:**
- `byte[] key`: khoá AES là mảng byte (không phải chuỗi). Khoá 256 bit = 32 byte.
- `Log(...)`: thêm một dòng vào ô log, dùng ở các bước đo thời gian.

### Bước 3. Yêu cầu 1: Sinh khoá AES

**Mục đích:** tạo khoá ngẫu nhiên đủ mạnh.

```csharp
private void btnGenKey_Click(object sender, EventArgs e)
{
    int bits = int.Parse(cboKeySize.SelectedItem.ToString());
    key = new byte[bits / 8];
    RandomNumberGenerator.Fill(key);              // sinh số ngẫu nhiên mật mã
    txtKey.Text = Convert.ToBase64String(key);
}
```

**Giải thích:**
- `bits / 8`: đổi bit sang byte (256 bit → 32 byte).
- `RandomNumberGenerator.Fill`: dùng bộ sinh số ngẫu nhiên **dành cho mật mã** của hệ điều hành. **Không dùng `Random`** vì dễ đoán, khoá sinh bằng `Random` không an toàn.
- `Convert.ToBase64String`: khoá là byte nhị phân, không hiển thị được trực tiếp; Base64 biến nó thành chuỗi chữ-số dễ xem và lưu.

### Bước 4. Yêu cầu 2: Lưu khoá ra file

**Mục đích:** giữ khoá lại để dùng lần sau (nếu mất khoá thì không giải mã được dữ liệu).

```csharp
private void btnSaveKey_Click(object sender, EventArgs e)
{
    if (key == null) { MessageBox.Show("Chưa có khoá"); return; }
    using var sfd = new SaveFileDialog { FileName = "aes.key" };
    if (sfd.ShowDialog() != DialogResult.OK) return;
    File.WriteAllText(sfd.FileName, Convert.ToBase64String(key));
}
```

**Giải thích:**
- `if (key == null)`: chặn lỗi khi chưa sinh khoá mà đã bấm Lưu.
- `SaveFileDialog`: hộp thoại chọn nơi lưu; `DialogResult.OK` nghĩa là người dùng đã bấm Save.
- Lưu khoá dạng chuỗi Base64 để mở bằng Notepad xem được. (Khoá là bí mật: không đưa file `.key` lên GitHub.)

### Bước 5. Yêu cầu 3: Nhập khoá từ file

**Mục đích:** đọc lại khoá đã lưu.

```csharp
private void btnLoadKey_Click(object sender, EventArgs e)
{
    using var ofd = new OpenFileDialog();
    if (ofd.ShowDialog() != DialogResult.OK) return;
    key = Convert.FromBase64String(File.ReadAllText(ofd.FileName).Trim());
    txtKey.Text = Convert.ToBase64String(key);
}
```

**Giải thích:**
- `FromBase64String` là phép ngược của `ToBase64String`, trả về đúng mảng byte khoá.
- `.Trim()` bỏ ký tự xuống dòng/khoảng trắng thừa ở cuối file, nếu không sẽ lỗi định dạng Base64.
- Kiểm tra: khoá hiện lên phải trùng khoá đã sinh.

### Bước 6. Yêu cầu 4: Mã hoá và giải mã văn bản

**Mục đích:** mã hoá một đoạn chữ rồi in kết quả ra màn hình.

```csharp
private void btnEncText_Click(object sender, EventArgs e)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();
    byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(txtPlain.Text), aes.IV);
    byte[] all = aes.IV.Concat(cipher).ToArray();
    txtCipher.Text = Convert.ToBase64String(all);          // kết quả ra màn hình
}

private void btnDecText_Click(object sender, EventArgs e)
{
    byte[] all = Convert.FromBase64String(txtCipher.Text.Trim());
    using var aes = Aes.Create();
    aes.Key = key;
    byte[] plain = aes.DecryptCbc(all[16..], all[..16]);
    txtPlain.Text = Encoding.UTF8.GetString(plain);
}
```

**Giải thích mã hoá:**
- `Aes.Create()`: tạo đối tượng AES; `using var` tự giải phóng khi xong.
- `aes.GenerateIV()`: sinh IV 16 byte ngẫu nhiên **mới cho mỗi lần mã hoá**.
- `Encoding.UTF8.GetBytes(...)`: AES chỉ mã hoá byte, nên đổi chữ (có dấu tiếng Việt) sang byte UTF-8.
- `EncryptCbc(dữ liệu, iv)`: mã hoá bằng chế độ CBC, mặc định đệm PKCS7.
- `aes.IV.Concat(cipher)`: ghép IV đứng trước bản mã, vì lúc giải mã cần IV (IV không bí mật).
- Hiển thị Base64 vì bản mã là byte nhị phân.

**Giải thích giải mã:**
- `all[..16]` là 16 byte đầu (IV), `all[16..]` là phần còn lại (bản mã).
- `DecryptCbc(bản mã, iv)` trả về byte gốc, đổi lại thành chữ bằng `GetString`.
- **Quan sát cho báo cáo:** mã hoá cùng một câu hai lần thì bản mã khác nhau (do IV khác) nhưng giải mã đều ra đúng câu gốc.
- Sai khoá sẽ báo lỗi `CryptographicException` (padding không hợp lệ).

### Bước 7. Yêu cầu 5: Mã hoá và giải mã file (hỗ trợ file hàng GB)

**Mục đích:** mã hoá nguyên file, kể cả file vài GB, mà không tốn RAM.

```csharp
static void EncryptFile(byte[] key, string src, string dst)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();
    using var fin  = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
    using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
    fout.Write(aes.IV, 0, 16);                                   // ghi IV đầu file
    using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
    fin.CopyTo(cs, 1 << 20);                                     // đệm 1 MB
}

static void DecryptFile(byte[] key, string src, string dst)
{
    using var aes = Aes.Create();
    aes.Key = key;
    using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
    byte[] iv = new byte[16];
    fin.ReadExactly(iv, 0, 16);
    aes.IV = iv;
    using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
    using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fout, 1 << 20);
}
```

**Giải thích:**
- **Vì sao dùng luồng (stream)?** Nếu dùng `File.ReadAllBytes` với file 3 GB thì nạp 3 GB vào RAM, dễ tràn bộ nhớ. Dùng `FileStream` + `CryptoStream` thì chỉ đọc từng mảnh nhỏ (`1 << 20` = 1.048.576 byte = 1 MB) rồi mã hoá và ghi ra ngay. Bộ nhớ dùng không đổi dù file lớn thế nào.
- `CryptoStream`: "ống" tự động mã hoá/giải mã dữ liệu chảy qua nó.
- `CopyTo(cs, 1 << 20)`: đọc từng khối 1 MB từ file nguồn đẩy vào ống mã hoá.
- Ghi IV 16 byte vào **đầu file `.enc`**, khi giải mã đọc lại 16 byte đầu để lấy IV.
- Khi các `using` kết thúc, `CryptoStream` mới ghi khối cuối (có padding); vì vậy không được bỏ `using`.
- `FileShare.Read/None`: kiểm soát việc chương trình khác có được mở file cùng lúc không.

Nút chọn file nguồn:
```csharp
private void btnBrowse_Click(object sender, EventArgs e)
{
    using var ofd = new OpenFileDialog();
    if (ofd.ShowDialog() == DialogResult.OK) txtSrc.Text = ofd.FileName;
}
```

### Bước 8. Tạo file lớn (hàng GB) để thử nghiệm

**Mục đích:** đề yêu cầu thử với file hàng GB; bạn có thể không có sẵn file lớn nên tạo bằng dữ liệu ngẫu nhiên.

```csharp
private void btnMakeFile_Click(object sender, EventArgs e)
{
    using var sfd = new SaveFileDialog { FileName = "test_data.bin" };
    if (sfd.ShowDialog() != DialogResult.OK) return;
    long total = (long)numMb.Value * 1024 * 1024;
    byte[] buf = new byte[4 << 20];
    using var fs = new FileStream(sfd.FileName, FileMode.Create);
    for (long written = 0; written < total; )
    {
        RandomNumberGenerator.Fill(buf);
        int n = (int)Math.Min(buf.Length, total - written);
        fs.Write(buf, 0, n);
        written += n;
    }
    txtSrc.Text = sfd.FileName;
    Log("Đã tạo file " + sfd.FileName);
}
```

**Giải thích:**
- `(long)numMb.Value * 1024 * 1024`: đổi MB sang byte; **phải ép `long`** vì 3 GB = 3.221.225.472 vượt giới hạn `int` (~2,1 tỉ).
- Ghi từng khối 4 MB ngẫu nhiên cho tới khi đủ dung lượng; khối cuối ngắn hơn nên dùng `Math.Min`.
- **Thử các kích thước:** 100 MB, 1024 MB, 3072 MB để có số liệu so sánh.
- **Dung lượng ổ đĩa:** cần ~3 lần kích thước file (nguồn + `.enc` + `.dec`). Xoá file thử sau khi xong.

### Bước 9. Đo thời gian mã hoá và giải mã

**Mục đích:** có số liệu cho phần kết luận.

```csharp
private void btnEncFile_Click(object sender, EventArgs e)
{
    string src = txtSrc.Text;
    var sw = Stopwatch.StartNew();
    EncryptFile(key, src, src + ".enc");
    sw.Stop();
    long size = new FileInfo(src).Length;
    Log($"Mã hoá {size / 1048576.0:F0} MB: {sw.Elapsed.TotalSeconds:F2} giây ({size / 1048576.0 / sw.Elapsed.TotalSeconds:F1} MB/s)");
}

private void btnDecFile_Click(object sender, EventArgs e)
{
    string src = txtSrc.Text;
    var sw = Stopwatch.StartNew();
    DecryptFile(key, src + ".enc", src + ".dec");
    sw.Stop();
    Log($"Giải mã: {sw.Elapsed.TotalSeconds:F2} giây");
}
```

**Giải thích:**
- `Stopwatch`: đồng hồ bấm giờ độ chính xác cao; `StartNew()` bắt đầu, `Stop()` dừng, `Elapsed` là thời gian đã trôi.
- `size / 1048576.0`: đổi byte sang MB (1 MB = 1.048.576 byte), chia cho giây để ra **tốc độ MB/s**, dễ so sánh giữa các file.
- `F2`, `F1`: làm tròn 2 hoặc 1 chữ số thập phân.
- File `.enc` và `.dec` được đặt cạnh file nguồn bằng cách nối đuôi tên.
- **Lưu ý giao diện:** file vài GB làm form "đứng" trong lúc xử lý (vì chạy trên luồng giao diện). Muốn mượt hơn, đổi hàm thành `async` và bọc: `await Task.Run(() => EncryptFile(...));`. Đo thời gian vẫn đúng.

### Bước 10. So sánh theo byte: file nguồn và file giải mã

**Mục đích:** chứng minh giải mã trả lại đúng dữ liệu ban đầu.

```csharp
private void btnCompare_Click(object sender, EventArgs e)
{
    string a = txtSrc.Text, b = txtSrc.Text + ".dec";
    using var fa = File.OpenRead(a);
    using var fb = File.OpenRead(b);
    if (fa.Length != fb.Length) { Log("KHÁC: độ dài khác nhau"); return; }
    byte[] ba = new byte[1 << 20], bb = new byte[1 << 20];
    long offset = 0;
    while (offset < fa.Length)
    {
        int n = fa.Read(ba, 0, ba.Length);
        fb.ReadExactly(bb, 0, n);
        if (!ba.AsSpan(0, n).SequenceEqual(bb.AsSpan(0, n))) { Log("KHÁC nhau quanh offset " + offset); return; }
        offset += n;
    }
    Log("GIỐNG NHAU hoàn toàn từng byte");
}
```

**Giải thích:**
- Kiểm tra độ dài trước: khác độ dài thì chắc chắn khác, khỏi so tiếp.
- So từng khối 1 MB thay vì nạp cả file vào RAM.
- `SequenceEqual`: so hai đoạn byte từng phần tử một.
- `ReadExactly(bb, 0, n)`: đọc đủ `n` byte từ file thứ hai (đảm bảo hai khối so sánh cùng kích thước).
- Nếu "GIỐNG NHAU" thì AES mã hoá/giải mã đúng, không mất dữ liệu.

### Bước 11. Ghi số liệu và viết kết luận

**Mục đích:** đề yêu cầu "kết luận dựa theo số liệu thu được".

1. Với mỗi kích thước file, chép vào bảng (Word/Excel):

| Kích thước | Mã hoá (s) | Giải mã (s) | Tốc độ mã hoá (MB/s) | So sánh byte |
|---|---|---|---|---|
| 100 MB | ... | ... | ... | Giống |
| 1 GB | ... | ... | ... | Giống |
| 3 GB | ... | ... | ... | Giống |

2. Rút kết luận từ **số liệu của chính bạn** (đừng chép số của người khác):
   - **Quan hệ với kích thước:** kích thước tăng bao nhiêu lần thì thời gian tăng gần bấy nhiêu lần, tức độ phức tạp tuyến tính O(n).
   - **Mã hoá và giải mã:** so tốc độ hai chiều (thường xấp xỉ nhau; giải mã CBC có thể nhanh hơn chút vì song song hoá được).
   - **Tính đúng đắn:** file giải mã trùng khớp từng byte.
   - **Ưu/nhược:** AES rất nhanh, hợp với dữ liệu lớn; khó khăn là bảo vệ và trao đổi khoá, dẫn đến nhu cầu dùng RSA (Bài 2).
   - **Yếu tố ảnh hưởng tốc độ:** ổ cứng (HDD/SSD), CPU có hỗ trợ lệnh AES-NI hay không.

---

## PHẦN 3. BÀI 2: MÃ HOÁ RSA (project `Bai2_RSA`)

Thêm `using System.Numerics;` (cho `BigInteger`, dùng để hiển thị số rất lớn).

### Bước 1. Giao diện và biến dùng chung

**Mục đích:** dùng **TabControl** (Toolbox → Containers → TabControl) với các tab: Khoá & PEM, Xem PEM, Mã hoá/Giải mã, Tốc độ, SHA-256, Chữ ký số. Mỗi tab kéo thêm TextBox (Multiline) và Button cho từng bước dưới đây.

```csharp
string pubPem, privPem;           // khoá đang dùng ở dạng PEM
```

**Giải thích:** lưu khoá ở dạng chuỗi PEM để mọi nút đều dùng chung; mỗi lần cần dùng thì tạo đối tượng `RSA` từ chuỗi này (`ImportFromPem`).

### Bước 2. Yêu cầu 1, 2: Sinh cặp khoá và xuất PEM

**Mục đích:** tạo cặp khoá RSA và lưu thành hai file `.pem`.

```csharp
private void btnGen_Click(object sender, EventArgs e)
{
    using var rsa = RSA.Create(2048);
    pubPem  = rsa.ExportSubjectPublicKeyInfoPem();   // BEGIN PUBLIC KEY
    privPem = rsa.ExportPkcs8PrivateKeyPem();        // BEGIN PRIVATE KEY
    txtPub.Text = pubPem;
    txtPriv.Text = privPem;
}

private void btnSavePem_Click(object sender, EventArgs e)
{
    File.WriteAllText(@"D:\public.pem", pubPem);     // hoặc dùng SaveFileDialog
    File.WriteAllText(@"D:\private.pem", privPem);
}
```

**Giải thích:**
- `RSA.Create(2048)`: sinh cặp khoá 2048 bit (tìm hai số nguyên tố lớn p, q nên mất vài trăm mili giây; 4096 bit có thể mất vài giây).
- `ExportSubjectPublicKeyInfoPem()`: xuất **public key** theo chuẩn SPKI (nhãn `BEGIN PUBLIC KEY`).
- `ExportPkcs8PrivateKeyPem()`: xuất **private key** theo chuẩn PKCS#8 (nhãn `BEGIN PRIVATE KEY`), chứa đủ n, e, d, p, q...
- **Quy tắc an toàn:** public key có thể gửi cho mọi người; private key phải giữ bí mật, không đưa lên GitHub.

### Bước 3. Yêu cầu 3: Xem PEM và ý nghĩa các byte

**Mục đích:** hiểu bên trong file PEM có gì.

**Cấu trúc cần trình bày trong báo cáo:**
- Dòng `-----BEGIN ...-----` và `-----END ...-----` là **nhãn** cho biết loại dữ liệu.
- Phần giữa là **Base64** của dữ liệu nhị phân **DER** (cứ 4 ký tự Base64 = 3 byte, mỗi dòng 64 ký tự).
- DER theo chuẩn ASN.1 dạng **TLV** (Type-Length-Value): mỗi phần tử gồm 1 byte Tag, byte(s) độ dài, rồi nội dung.

| Tag | Ý nghĩa |
|---|---|
| `30` | SEQUENCE: nhóm các phần tử con |
| `02` | INTEGER: số nguyên lớn (n, e, d...) |
| `03` | BIT STRING |
| `04` | OCTET STRING |
| `05` | NULL |
| `06` | OBJECT IDENTIFIER (OID): định danh thuật toán, ví dụ `1.2.840.113549.1.1.1` là rsaEncryption |

- **Độ dài:** nhỏ hơn `0x80` thì chính là độ dài; dạng `0x8N` thì N byte kế tiếp là độ dài. Ví dụ `82 01 0A` = 0x010A = 266 byte.
- **Byte `00` đầu INTEGER:** số dương có bit cao bằng 1 phải thêm `00` phía trước để không bị hiểu là số âm; vì vậy n 2048 bit thường dài 257 byte và bắt đầu bằng `00`.
- **Ví dụ e = 65537:** `02 03 01 00 01` (Tag INTEGER, dài 3 byte, giá trị 0x010001).
- **Public key:** `SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { SEQUENCE { n, e } } }`.
- **Private key:** `SEQUENCE { version 0, SEQUENCE { OID, NULL }, OCTET STRING { SEQUENCE { 0, n, e, d, p, q, dP, dQ, qInv } } }`.

Code lấy byte DER và in hex để đối chiếu:
```csharp
private void btnViewPem_Click(object sender, EventArgs e)
{
    string pem = txtPriv.Text;
    var f = PemEncoding.Find(pem);
    byte[] der = Convert.FromBase64String(pem[f.Base64Data].ToString());
    txtView.Text = $"Nhãn: {pem[f.Label]}, DER dài {der.Length} byte\r\n" + Convert.ToHexString(der);
}
```

**Giải thích:**
- `PemEncoding.Find`: tìm vị trí nhãn và phần Base64 trong chuỗi PEM.
- `Convert.FromBase64String`: giải Base64 để có byte DER.
- `Convert.ToHexString`: in hex để bạn gạch chân từng đoạn theo các tag `30 02 03 04 06` ở bảng trên và giải thích trong báo cáo. (Bản đầy đủ có bộ phân tích tự động trong `Bai2_RSA/Asn1.cs`.)

### Bước 4. Yêu cầu 4: Nhập PEM, lấy n, e (public) và n, e, d... (private)

**Mục đích:** đọc file PEM trở lại thành các số của khoá.

```csharp
private void btnImport_Click(object sender, EventArgs e)
{
    using var ofd = new OpenFileDialog();
    if (ofd.ShowDialog() != DialogResult.OK) return;
    string text = File.ReadAllText(ofd.FileName);

    using var rsa = RSA.Create();
    rsa.ImportFromPem(text);                         // tự nhận public hoặc private
    bool isPrivate = text.Contains("PRIVATE KEY");
    RSAParameters p = rsa.ExportParameters(isPrivate);

    var sb = new StringBuilder();
    sb.AppendLine("n = " + Convert.ToHexString(p.Modulus));
    sb.AppendLine("e = " + new BigInteger(p.Exponent, true, true));
    if (isPrivate)
    {
        sb.AppendLine("d  = " + Convert.ToHexString(p.D));
        sb.AppendLine("p  = " + Convert.ToHexString(p.P));
        sb.AppendLine("q  = " + Convert.ToHexString(p.Q));
        sb.AppendLine("dP = " + Convert.ToHexString(p.DP));
        sb.AppendLine("dQ = " + Convert.ToHexString(p.DQ));
        sb.AppendLine("qInv = " + Convert.ToHexString(p.InverseQ));
        privPem = text;
        pubPem = rsa.ExportSubjectPublicKeyInfoPem();
    }
    else pubPem = text;
    txtParams.Text = sb.ToString();
}
```

**Giải thích:**
- `ImportFromPem`: nạp khoá từ PEM, tự nhận là public hay private.
- `ExportParameters(true/false)`: lấy các thành phần. `false` chỉ trả n và e; `true` trả đủ d, p, q... (chỉ làm được khi nạp private key).
- `RSAParameters`: `Modulus` = n, `Exponent` = e, `D` = d, `P`, `Q`, `DP` = d mod (p−1), `DQ` = d mod (q−1), `InverseQ` = q⁻¹ mod p.
- `new BigInteger(bytes, true, true)`: đổi mảng byte (không dấu, big-endian) thành số lớn để hiển thị; `e` sẽ ra `65537`.
- Khi nạp private key, public key được suy ra từ chính nó (`ExportSubjectPublicKeyInfoPem`).
- **Quan sát:** public key chỉ có n và e; private key có thêm d, p, q... Nếu biết n phân tích ra p, q thì tính được d, nên độ khó của việc phân tích số nguyên tố lớn chính là độ an toàn của RSA.

### Bước 5. Yêu cầu 5: Mã hoá dữ liệu (≤ 190 byte) bằng public key

**Mục đích:** mã hoá một khoá AES 32 byte bằng RSA, lưu bản mã Base64 ra file.

```csharp
private void btnEncrypt_Click(object sender, EventArgs e)
{
    byte[] data = RandomNumberGenerator.GetBytes(32);        // ví dụ khoá AES-256 (32 byte)
    txtData.Text = Convert.ToBase64String(data);

    using var rsa = RSA.Create();
    rsa.ImportFromPem(pubPem);
    byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OAEPSHA256);
    string b64 = Convert.ToBase64String(cipher);
    txtCipher.Text = b64;
    File.WriteAllText(@"D:\cipher_base64.txt", b64);          // lưu file
}
```

**Giải thích:**
- `GetBytes(32)`: 32 byte ngẫu nhiên = một khoá AES-256 (đúng ví dụ của đề). Hiển thị Base64 (44 ký tự) để so sánh về sau.
- `ImportFromPem(pubPem)`: chỉ cần **public key** để mã hoá.
- `OAEPSHA256`: kiểu đệm an toàn; quyết định giới hạn **190 byte** với khoá 2048 bit. Nếu dữ liệu dài hơn, `Encrypt` ném `CryptographicException`.
- Bản mã RSA luôn dài đúng bằng khoá (2048 bit = 256 byte), Base64 dài 344 ký tự.
- Mã hoá cùng dữ liệu hai lần cho hai bản mã khác nhau vì OAEP có thành phần ngẫu nhiên.

### Bước 6. Yêu cầu 6: Giải mã từ PEM và file Base64, rồi so sánh

**Mục đích:** chứng minh giải mã bằng private key trả lại đúng dữ liệu.

```csharp
private void btnDecrypt_Click(object sender, EventArgs e)
{
    string priv = File.ReadAllText(@"D:\private.pem");
    string b64  = File.ReadAllText(@"D:\cipher_base64.txt").Trim();

    using var rsa = RSA.Create();
    rsa.ImportFromPem(priv);
    byte[] plain = rsa.Decrypt(Convert.FromBase64String(b64), RSAEncryptionPadding.OAEPSHA256);

    byte[] original = Convert.FromBase64String(txtData.Text);
    txtResult.Text = plain.AsSpan().SequenceEqual(original) ? "GIỐNG dữ liệu gốc" : "KHÁC dữ liệu gốc";
}
```

**Giải thích:**
- Đầu vào đúng như đề: file PEM (private key) + file chứa dữ liệu mã hoá dạng Base64.
- **Phải dùng cùng kiểu đệm** (`OAEPSHA256`) như lúc mã hoá, nếu khác sẽ lỗi.
- Giải mã cần **private key**; dùng nhầm khoá khác cặp sẽ lỗi.
- `SequenceEqual` so mảng giải mã với dữ liệu gốc: "GIỐNG" là đạt.

### Bước 7. Yêu cầu 7: Đánh giá tốc độ (e nhỏ so với d lớn)

**Mục đích:** kiểm chứng bằng số liệu: thao tác dùng public key (e nhỏ) nhanh hơn thao tác dùng private key (d lớn).

```csharp
private void btnBench_Click(object sender, EventArgs e)
{
    using var priv = RSA.Create(); priv.ImportFromPem(privPem);
    using var pub  = RSA.Create(); pub.ImportFromPem(pubPem);
    byte[] data = RandomNumberGenerator.GetBytes(32);
    byte[] enc  = pub.Encrypt(data, RSAEncryptionPadding.OAEPSHA256);   // khởi động
    int N = 500;

    var sw = Stopwatch.StartNew();
    for (int i = 0; i < N; i++) pub.Encrypt(data, RSAEncryptionPadding.OAEPSHA256);
    double encMs = sw.Elapsed.TotalMilliseconds / N;

    sw.Restart();
    for (int i = 0; i < N; i++) priv.Decrypt(enc, RSAEncryptionPadding.OAEPSHA256);
    double decMs = sw.Elapsed.TotalMilliseconds / N;

    txtBench.Text = $"Mã hoá (public, e=65537): {encMs:F4} ms\r\n" +
                    $"Giải mã (private, d lớn): {decMs:F4} ms  (chậm hơn {decMs / encMs:F1} lần)";
}
```

**Giải thích:**
- Một lần mã hoá chỉ mất vài chục micro giây, quá ngắn để đo chính xác, nên lặp **N = 500 lần** rồi lấy trung bình.
- Chạy 1 lần "khởi động" trước khi đo để loại bỏ thời gian khởi tạo lần đầu.
- Mã hoá luỹ thừa với **e = 65537 (17 bit)** nên ít phép nhân; giải mã luỹ thừa với **d cỡ 2048 bit** nên nhiều phép nhân hơn nhiều, vì vậy chậm hơn.
- **Cách thử mở rộng:** lặp lại với khoá 1024, 2048, 3072, 4096 bit và ghi bảng. Kết luận mẫu: dùng private key chậm hơn nhiều lần public key; khoá càng dài càng an toàn nhưng càng chậm; sinh khoá là bước tốn thời gian nhất.

### Bước 8. Yêu cầu 8: Băm SHA-256 và đánh giá thay đổi

**Mục đích:** thấy rằng thay đổi rất nhỏ ở đầu vào làm đầu ra băm thay đổi hoàn toàn.

Tạo TextBox `txtIn`, TextBox `txtHash`, TextBox `txtHashLog` (Multiline). Xử lý sự kiện `TextChanged` của `txtIn`:

```csharp
byte[] prevHash;

private void txtIn_TextChanged(object sender, EventArgs e)
{
    byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes(txtIn.Text));
    txtHash.Text = Convert.ToHexString(h);

    if (prevHash != null)
    {
        int diff = 0;
        for (int i = 0; i < 32; i++)
            diff += BitOperations.PopCount((uint)(h[i] ^ prevHash[i]));
        txtHashLog.AppendText($"Khác {diff}/256 bit ({diff / 2.56:F1}%)\r\n");
    }
    prevHash = h;
}
```

(Thêm `using System.Numerics;` để dùng `BitOperations`.)

**Giải thích:**
- `TextChanged` chạy mỗi khi bạn gõ hoặc xoá một ký tự nên băm cập nhật tức thì.
- SHA-256 luôn cho đầu ra cố định 256 bit = 32 byte = 64 ký tự hex, bất kể đầu vào dài hay ngắn.
- `h[i] ^ prevHash[i]` (XOR): bit nào khác nhau thì ra 1; `PopCount` đếm số bit 1, tức số bit khác nhau giữa hai lần băm.
- `diff / 2.56`: đổi số bit khác (trên 256) sang phần trăm.
- **Kết quả để báo cáo:** thử `hello` rồi `hellp` (đổi 1 ký tự): khoảng **50%** (≈ 128/256) số bit thay đổi. Đây là **hiệu ứng tuyết lở**: không thể đoán đầu vào từ đầu ra, hai đầu vào gần nhau cho băm hoàn toàn khác nhau.
- Cùng đầu vào luôn cho cùng giá trị băm (tính xác định).

### Bước 9. Yêu cầu 9: Chữ ký số, và đề xuất để mỗi lần ký ra chữ ký khác nhau

**Mục đích:** hiểu chữ ký số và giải quyết bài toán "ký nhiều lần ra nhiều chữ ký khác nhau".

**Nguyên lý chữ ký số:**
1. Người ký tính **băm SHA-256** của dữ liệu.
2. Dùng **private key** "mã hoá" giá trị băm đó ra chữ ký.
3. Người nhận dùng **public key** giải chữ ký, so với băm do chính mình tính; khớp thì dữ liệu nguyên vẹn và đúng người ký.
- Dữ liệu khác nhau → băm khác → chữ ký khác (với cùng người ký). Dữ liệu bị sửa dù 1 ký tự thì chữ ký cũ không còn hợp lệ.

```csharp
private void btnSign_Click(object sender, EventArgs e)
{
    byte[] data = Encoding.UTF8.GetBytes(txtSignData.Text);
    using var priv = RSA.Create(); priv.ImportFromPem(privPem);
    using var pub  = RSA.Create(); pub.ImportFromPem(pubPem);

    var sb = new StringBuilder();
    for (int i = 1; i <= 3; i++)
    {
        byte[] s = priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        sb.AppendLine($"PKCS1 lần {i}: {Convert.ToBase64String(s)[..40]}...");
    }
    for (int i = 1; i <= 3; i++)
    {
        byte[] s = priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        bool ok = pub.VerifyData(data, s, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        sb.AppendLine($"PSS   lần {i}: {Convert.ToBase64String(s)[..40]}...  hợp lệ={ok}");
    }
    txtSignOut.Text = sb.ToString();
}
```

**Giải thích:**
- `SignData(dữ liệu, SHA256, padding)`: tự băm bằng SHA-256 rồi ký bằng private key.
- `VerifyData(dữ liệu, chữ ký, SHA256, padding)`: xác thực bằng public key, trả về `true/false`. Phải dùng **đúng cùng kiểu padding** khi ký và khi xác thực.
- `Pkcs1` (PKCS#1 v1.5): kiểu **xác định**: cùng dữ liệu + cùng khoá luôn ra **chữ ký y hệt nhau**. Đây là điều đề muốn thay đổi.
- `Pss` (RSASSA-PSS): kiểu **ngẫu nhiên hoá**: mỗi lần ký ra chữ ký **khác nhau** nhưng đều hợp lệ.
- `[..40]`: chỉ hiển thị 40 ký tự đầu của chữ ký (chữ ký dài 344 ký tự Base64) cho dễ nhìn.

**Phương pháp đề xuất cho mong muốn của đề (cùng dữ liệu, cùng người ký nhưng chữ ký khác nhau):**

1. **RSASSA-PSS (khuyên dùng).**
   - Cách hoạt động: mỗi lần ký, chương trình sinh một **salt ngẫu nhiên**, ghép với giá trị băm rồi băm tiếp và che bằng hàm MGF1 để tạo khối dữ liệu đem đi luỹ thừa bằng private key. Salt khác thì khối khác, nên chữ ký khác.
   - Vẫn xác thực được: salt được cất sẵn **bên trong chính chữ ký**, nên người nhận tự khôi phục salt và kiểm tra, không cần gửi thêm thông tin.
   - Ưu điểm: có chứng minh an toàn chặt chẽ, là chuẩn hiện đại (PKCS#1 v2.1, RFC 8017), .NET hỗ trợ sẵn.

2. **Ghép nonce vào dữ liệu trước khi băm.**
   - Mỗi lần ký sinh một nonce ngẫu nhiên (hoặc dùng dấu thời gian), ký `H(dữ liệu ‖ nonce)`, rồi gửi kèm bộ ba `(dữ liệu, nonce, chữ ký)`.
   - Nhược điểm: phải truyền thêm nonce, dễ làm sai giao thức.

**Lợi ích của việc ngẫu nhiên hoá chữ ký:** tránh bị theo dõi/so khớp việc cùng một nội dung được ký lặp lại, và PSS an toàn hơn PKCS#1 v1.5.

**Kết quả để báo cáo:** 3 chữ ký PKCS#1 giống hệt nhau; 3 chữ ký PSS khác nhau nhưng đều `hợp lệ = True`. Chụp màn hình làm minh chứng.

---

## PHẦN 4. ĐƯA BÀI LÊN GITHUB

**Mục đích:** nộp bài hoặc lưu trữ mã nguồn.

1. Kiểm tra Git: mở cmd, gõ `git --version`. Nếu chưa có, cài Git for Windows.
2. **Cách dễ nhất trong Visual Studio:** menu **Git → Create Git Repository** → chọn GitHub → đăng nhập → đặt tên repo → chọn **Private** nếu chưa muốn công khai → **Create and Push**.
3. Hoặc dùng dòng lệnh (tạo repo trống trên github.com trước):

```
git init
git add .
git commit -m "Bai tap ATTT: AES va RSA"
git branch -M main
git remote add origin https://github.com/TEN_BAN/TEN_REPO.git
git push -u origin main
```

**Giải thích các lệnh:**
- `git init`: biến thư mục thành kho Git.
- `git add .`: đưa mọi thay đổi vào danh sách chờ commit.
- `git commit -m "..."`: chốt một phiên bản kèm ghi chú.
- `git branch -M main`: đặt tên nhánh chính là `main`.
- `git remote add origin ...`: gắn địa chỉ repo trên GitHub.
- `git push -u origin main`: đẩy mã lên GitHub.

4. **Trước khi push:** kiểm tra `.gitignore` đã loại `bin/`, `obj/`, `.vs/`, `*.pem`, `*.key`, `*.enc`, `*.dec`, `*.bin`. **Không đưa private key và file dữ liệu lớn lên GitHub.** Nếu lỡ đẩy, hãy đổi khoá ngay vì xoá file sau đó không xoá được lịch sử commit.

---

## DANH SÁCH KIỂM TRA TRƯỚC KHI NỘP

- [ ] Bài 1: sinh/lưu/nạp khoá, mã hoá văn bản, mã hoá file hoạt động
- [ ] Bài 1: đã thử file lớn (≥ 1 GB), có bảng thời gian và kết quả so sánh byte
- [ ] Bài 1: có kết luận dựa trên số liệu
- [ ] Bài 2: sinh khoá, xuất PEM, xem PEM, nhập PEM đọc được n, e, d
- [ ] Bài 2: mã hoá 32 byte, lưu Base64, giải mã và so sánh khớp
- [ ] Bài 2: có số liệu tốc độ, thử đổi 1 ký tự khi băm, chữ ký số và đề xuất PSS
- [ ] Đã đưa lên GitHub, không lộ private key
