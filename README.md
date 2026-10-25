# BÀI TẬP AN TOÀN VÀ BẢO MẬT THÔNG TIN

- **Nguyễn Minh Hạnh** 
- **Lớp: K59KMT** 


# BÀI 1: MÃ HOÁ AES (đối xứng)

**Kiến thức cần nắm:** AES xử lý từng khối 16 byte; khoá 128/192/256 bit (16/24/32 byte). Chế độ **CBC** cần **IV** 16 byte ngẫu nhiên (không bí mật, phải khác nhau mỗi lần mã hoá). Đệm **PKCS7** để đủ khối cuối.

## Thiết kế giao diện Bài 1 (làm một lần)

| Điều khiển | (Name) | Ghi chú |
|---|---|---|
| ComboBox | `cboKeySize` | Items: 128, 192, 256; đặt Text mặc định 256 |
| Button | `btnGenKey`, `btnSaveKey`, `btnLoadKey` | Sinh / Lưu / Nạp khoá |
| TextBox | `txtKey` | Multiline, ReadOnly: hiện khoá Base64 |
| TextBox | `txtPlain`, `txtCipher` | Multiline: văn bản gốc, bản mã |
| Button | `btnEncText`, `btnDecText` | Mã hoá / Giải mã văn bản |
| TextBox | `txtSrc` | Đường dẫn file nguồn |
| Button | `btnBrowse`, `btnMakeFile`, `btnEncFile`, `btnDecFile`, `btnCompare` | Chọn file, tạo file thử, mã hoá, giải mã, so sánh |
| NumericUpDown | `numMb` | Kích thước file thử (MB), Maximum = 100000 |
| TextBox | `txtLog` | Multiline, ReadOnly, ScrollBars = Vertical |

Biến dùng chung trong class `Form1`:

```csharp
byte[] key;                                   // khoá AES hiện tại
void Log(string s) => txtLog.AppendText(s + Environment.NewLine);
```

`key` là mảng byte (không phải chuỗi) và được dùng chung giữa các nút.

---

## 1. Sinh khoá AES

**Cách làm:** bấm đúp `btnGenKey`, dán code:

```csharp
private void btnGenKey_Click(object sender, EventArgs e)
{
    int bits = int.Parse(cboKeySize.Text);
    key = new byte[bits / 8];
    RandomNumberGenerator.Fill(key);              // số ngẫu nhiên dùng cho mật mã
    txtKey.Text = Convert.ToBase64String(key);
}
```

![alt text](<sinh khóa .png>)

**Giải thích:**
- `bits / 8`: đổi bit sang byte (256 bit → 32 byte).
- `RandomNumberGenerator.Fill`: bộ sinh ngẫu nhiên **dành cho mật mã**. Không dùng `Random` vì dễ đoán.
- `ToBase64String`: khoá là byte nhị phân không hiển thị được, Base64 biến nó thành chuỗi chữ-số.

**Kiểm tra:** bấm nút, `txtKey` hiện chuỗi Base64 (khoá 256 bit → 44 ký tự).

---

## 2. Lưu khoá ra file

**Cách làm:** bấm đúp `btnSaveKey`:

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
- `if (key == null)`: chặn lỗi khi chưa sinh khoá.
- `SaveFileDialog`: hộp thoại chọn nơi lưu; `DialogResult.OK` là người dùng đã bấm Save.
- Lưu dạng Base64 để mở bằng Notepad xem được.

**Kiểm tra:** mở file `aes.key` bằng Notepad, nội dung trùng với `txtKey`. File này là bí mật, không đưa lên GitHub.

---

## 3. Import khoá từ file

**Cách làm:** bấm đúp `btnLoadKey`:

```csharp
private void btnLoadKey_Click(object sender, EventArgs e)
{
    using var ofd = new OpenFileDialog();
    if (ofd.ShowDialog() != DialogResult.OK) return;
    byte[] k = Convert.FromBase64String(File.ReadAllText(ofd.FileName).Trim());
    if (k.Length != 16 && k.Length != 24 && k.Length != 32)
    {
        MessageBox.Show("Khoá không hợp lệ (cần 16, 24 hoặc 32 byte)");
        return;
    }
    key = k;
    txtKey.Text = Convert.ToBase64String(key);
}
```

**Giải thích:**
- `FromBase64String` là phép ngược của `ToBase64String`.
- `.Trim()` bỏ ký tự xuống dòng thừa cuối file, nếu không sẽ lỗi định dạng.
- Kiểm tra độ dài vì AES chỉ nhận 16, 24 hoặc 32 byte.

**Kiểm tra:** sinh khoá → lưu → sinh khoá khác → nạp lại file: `txtKey` phải quay về khoá cũ.

---

## 4. Mã hoá một đoạn văn bản, kết quả hiện ra màn hình

**Cách làm:** bấm đúp `btnEncText` và `btnDecText`:

```csharp
private void btnEncText_Click(object sender, EventArgs e)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();                                         // IV mới mỗi lần
    byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(txtPlain.Text), aes.IV);
    byte[] all = aes.IV.Concat(cipher).ToArray();             // IV đứng trước bản mã
    txtCipher.Text = Convert.ToBase64String(all);             // kết quả ra màn hình
}

private void btnDecText_Click(object sender, EventArgs e)
{
    byte[] all = Convert.FromBase64String(txtCipher.Text.Trim());
    using var aes = Aes.Create();
    aes.Key = key;
    byte[] plain = aes.DecryptCbc(all[16..], all[..16]);      // (bản mã, IV)
    txtPlain.Text = Encoding.UTF8.GetString(plain);
}
```

**Giải thích:**
- `Encoding.UTF8.GetBytes`: AES chỉ mã hoá byte, nên đổi chữ (kể cả có dấu tiếng Việt) sang byte UTF-8.
- `EncryptCbc(dữ liệu, iv)`: mã hoá CBC, mặc định đệm PKCS7.
- Ghép IV vào đầu bản mã vì lúc giải mã cần IV (IV không bí mật).
- `all[..16]` là IV, `all[16..]` là bản mã.

![alt text](<sau khi mã hóa.png>)

**Kiểm tra:** mã hoá → xoá ô gốc → giải mã: ra lại đúng câu cũ. Mã hoá hai lần cùng một câu cho hai bản mã **khác nhau** (IV khác).

---

## 5. Mã hoá một file, lưu vào một file

**Cách làm:** thêm hai hàm (đặt trong class `Form1`) rồi bấm đúp `btnBrowse` để chọn file:

```csharp
static void EncryptFile(byte[] key, string src, string dst)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();
    using var fin  = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
    using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
    fout.Write(aes.IV, 0, 16);                                // ghi IV ở đầu file
    using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
    fin.CopyTo(cs, 1 << 20);                                  // từng khối 1 MB
}

static void DecryptFile(byte[] key, string src, string dst)
{
    using var aes = Aes.Create();
    aes.Key = key;
    using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
    byte[] iv = new byte[16];
    fin.ReadExactly(iv, 0, 16);                               // đọc IV từ đầu file
    aes.IV = iv;
    using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
    using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fout, 1 << 20);
}

private void btnBrowse_Click(object sender, EventArgs e)
{
    using var ofd = new OpenFileDialog();
    if (ofd.ShowDialog() == DialogResult.OK) txtSrc.Text = ofd.FileName;
}
```

**Giải thích:**
- **Vì sao dùng luồng (stream):** nạp cả file 3 GB vào RAM sẽ tràn bộ nhớ. `FileStream` + `CryptoStream` đọc từng khối 1 MB (`1 << 20` = 1.048.576 byte), mã hoá rồi ghi ngay, nên bộ nhớ dùng không đổi dù file lớn thế nào.
- Ghi IV 16 byte vào đầu file `.enc`; giải mã đọc lại 16 byte đầu để lấy IV.
- Các `using` kết thúc thì `CryptoStream` mới ghi nốt khối cuối (có đệm), nên đừng bỏ `using`.

![alt text](<file 100mb.png>)

**Kiểm tra:** chọn một file nhỏ (ví dụ ảnh) → mã hoá thành `.enc` → giải mã thành `.dec` → mở `.dec` thấy ảnh giống bản gốc.

---

## Bổ sung. Thử với file lớn (hàng GB)

**Cách làm:** bấm đúp `btnMakeFile`:

```csharp
private void btnMakeFile_Click(object sender, EventArgs e)
{
    using var sfd = new SaveFileDialog { FileName = "test_data.bin" };
    if (sfd.ShowDialog() != DialogResult.OK) return;
    long total = (long)numMb.Value * 1024 * 1024;
    byte[] buf = new byte[4 << 20];                           // khối 4 MB
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
- `(long)numMb.Value`: phải ép `long` vì 3 GB = 3.221.225.472 byte vượt giới hạn `int`.
- Ghi từng khối 4 MB ngẫu nhiên đến khi đủ dung lượng; khối cuối ngắn hơn nên dùng `Math.Min`.

**Nên thử:** 100 MB, 1024 MB (1 GB), 3072 MB (3 GB). Ổ đĩa cần trống khoảng **3 lần** dung lượng file (nguồn, `.enc`, `.dec`); xoá file thử khi xong.

---

## Bổ sung. Tính thời gian mã hoá và thời gian giải mã

**Cách làm:** bấm đúp `btnEncFile` và `btnDecFile`:

```csharp
private void btnEncFile_Click(object sender, EventArgs e)
{
    string src = txtSrc.Text;
    var sw = Stopwatch.StartNew();
    EncryptFile(key, src, src + ".enc");
    sw.Stop();
    long size = new FileInfo(src).Length;
    Log($"Mã hoá {size / 1048576.0:F0} MB: {sw.Elapsed.TotalSeconds:F2} giây " +
        $"({size / 1048576.0 / sw.Elapsed.TotalSeconds:F1} MB/s)");
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
- `Stopwatch`: đồng hồ bấm giờ chính xác cao; `StartNew()` bắt đầu, `Stop()` dừng, `Elapsed` là thời gian trôi qua.
- `size / 1048576.0 / giây`: đổi byte sang MB rồi chia cho giây ra **tốc độ MB/s**, tiện so sánh giữa các file.
- `F2`, `F1`: làm tròn 2 hoặc 1 chữ số thập phân.
- File `.enc`, `.dec` được tạo cạnh file nguồn bằng cách nối đuôi tên.
- Với file nhiều GB, form sẽ "đứng" khi xử lý. Muốn mượt hơn, đổi hàm thành `async` và bọc: `await Task.Run(() => EncryptFile(...));`. Số đo thời gian vẫn đúng.

**Kiểm tra:** log hiện thời gian và tốc độ; ghi lại vào bảng số liệu.

---

## Bổ sung. So sánh theo byte: file nguồn và file giải mã

**Cách làm:** bấm đúp `btnCompare`:

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
        if (!ba.AsSpan(0, n).SequenceEqual(bb.AsSpan(0, n)))
        {
            Log("KHÁC nhau quanh offset " + offset);
            return;
        }
        offset += n;
    }
    Log("GIỐNG NHAU hoàn toàn từng byte");
}
```

**Giải thích:**
- Kiểm tra độ dài trước: khác độ dài thì chắc chắn khác.
- So từng khối 1 MB thay vì nạp cả file vào RAM.
- `SequenceEqual` so hai đoạn byte từng phần tử.
- `ReadExactly(bb, 0, n)` đảm bảo đọc đủ `n` byte từ file thứ hai.

**Kiểm tra:** thấy "GIỐNG NHAU" là AES mã hoá và giải mã đúng, không mất dữ liệu.

---

![alt text](<file 1024mb.png>) ![alt text](<file 3027 mb.png>)

## Bổ sung. Kết luận dựa theo số liệu thu được

**Cách làm:** chạy từng kích thước (100 MB, 1 GB, 3 GB), ghi vào bảng:

| Kích thước | Mã hoá (s) | Giải mã (s) | Tốc độ mã hoá (MB/s) | So sánh byte |
|---|---|---|---|---|
| 100 MB | | | | |
| 1 GB | | | | |
| 3 GB | | | | |

**Rút kết luận từ số liệu :**
- Kích thước tăng bao nhiêu lần thì thời gian tăng gần bấy nhiêu lần (tuyến tính, O(n)).
- So tốc độ mã hoá với giải mã.
- File giải mã trùng khớp từng byte, thuật toán đúng.
- AES nhanh, hợp với dữ liệu lớn; khó khăn là bảo vệ và trao đổi khoá, dẫn đến RSA (Bài 2).
- Tốc độ phụ thuộc ổ đĩa (HDD/SSD) và việc CPU có AES-NI.

---

# BÀI 2: MÃ HOÁ RSA (bất đối xứng)

**Kiến thức cần nắm:** n = p·q; public key (n, e), private key (n, d). Mã hoá `c = m^e mod n`, giải mã `m = c^d mod n`. Dùng đệm **OAEP-SHA256**: với khoá 2048 bit, dữ liệu tối đa 256 − 2×32 − 2 = **190 byte**.

## Thiết kế giao diện Bài 2 (làm một lần)

Kéo một **TabControl** (Toolbox → Containers) với 6 tab: *Sinh khoá & PEM*, *Xem/nhập PEM*, *Mã hoá & giải mã*, *Tốc độ*, *SHA-256*, *Chữ ký số*. Điều khiển ở mỗi mục được nêu ở phần "Cách làm" bên dưới (đặt tên theo code).

Biến dùng chung:

```csharp
string pubPem, privPem;           // khoá đang dùng, ở dạng PEM
```

---

## 1. Sinh cặp khoá

**Cách làm:** tab 1: ComboBox `cboBits` (Items 1024, 2048, 3072, 4096), Button `btnGen`, hai TextBox Multiline `txtPub`, `txtPriv`.

```csharp
private void btnGen_Click(object sender, EventArgs e)
{
    int bits = int.Parse(cboBits.Text);
    using var rsa = RSA.Create(bits);
    pubPem  = rsa.ExportSubjectPublicKeyInfoPem();   // BEGIN PUBLIC KEY
    privPem = rsa.ExportPkcs8PrivateKeyPem();        // BEGIN PRIVATE KEY
    txtPub.Text = pubPem;
    txtPriv.Text = privPem;
}
```

**Giải thích:** `RSA.Create(bits)` tìm hai số nguyên tố lớn p, q (2048 bit mất vài trăm mili giây, 4096 bit có thể vài giây). Hai hàm `Export...Pem` xuất khoá thành chuỗi PEM.

![alt text](<1.Sinh khóa.png>)

**Kiểm tra:** `txtPub` bắt đầu bằng `-----BEGIN PUBLIC KEY-----`, `txtPriv` bằng `-----BEGIN PRIVATE KEY-----`.

---

## 2. Xuất cặp khoá ra file (PEM)

**Cách làm:** thêm Button `btnSavePub`, `btnSavePriv`:

```csharp
private void SavePem(string pem, string name)
{
    if (pem == null) { MessageBox.Show("Chưa có khoá"); return; }
    using var sfd = new SaveFileDialog { FileName = name };
    if (sfd.ShowDialog() == DialogResult.OK) File.WriteAllText(sfd.FileName, pem);
}

private void btnSavePub_Click(object sender, EventArgs e)  => SavePem(pubPem,  "public.pem");
private void btnSavePriv_Click(object sender, EventArgs e) => SavePem(privPem, "private.pem");
```

**Giải thích:** PEM là file văn bản nên ghi bằng `WriteAllText`. **Private key phải giữ bí mật**, không đưa lên GitHub.

**Kiểm tra:** mở hai file bằng Notepad thấy đúng nội dung.

---

## 3. View PEM cùng ý nghĩa các byte trong format PEM

**Cách làm:** tab 2: Button `btnViewPem`, TextBox Multiline `txtView`.

```csharp
private void btnViewPem_Click(object sender, EventArgs e)
{
    string pem = txtPriv.Text;
    var f = PemEncoding.Find(pem);
    byte[] der = Convert.FromBase64String(pem[f.Base64Data].ToString());
    txtView.Text = $"Nhãn: {pem[f.Label]}, DER dài {der.Length} byte\r\n" +
                   Convert.ToHexString(der);
}
```

**Giải thích:** `PemEncoding.Find` tìm nhãn và phần Base64; Base64 giải ra **DER** (dữ liệu nhị phân). In hex rồi đối chiếu với bảng dưới để chú thích từng đoạn trong báo cáo. (Bản đầy đủ có bộ phân tích tự động ở `Bai2_RSA/Asn1.cs`.)

**Ý nghĩa các byte:**
- `-----BEGIN ...-----` / `-----END ...-----`: nhãn loại dữ liệu; phần giữa là Base64 của DER (4 ký tự = 3 byte, 64 ký tự mỗi dòng).
- DER dạng **Tag – Length – Value**:

| Tag | Ý nghĩa |
|---|---|
| `30` | SEQUENCE (nhóm các phần tử) |
| `02` | INTEGER (số nguyên lớn) |
| `03` | BIT STRING |
| `04` | OCTET STRING |
| `05` | NULL |
| `06` | OBJECT IDENTIFIER (OID) |

- **Độ dài:** nhỏ hơn `0x80` thì là độ dài thật; dạng `0x8N` thì N byte sau là độ dài (ví dụ `82 01 0A` = 266 byte).
- **Byte `00` đầu INTEGER:** thêm vào khi bit cao bằng 1 để không bị hiểu là số âm (nên n 2048 bit dài 257 byte).
- **e = 65537:** `02 03 01 00 01`.
- **Public key:** `SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { SEQUENCE { n, e } } }`.
- **Private key:** `SEQUENCE { 0, SEQUENCE { OID, NULL }, OCTET STRING { SEQUENCE { 0, n, e, d, p, q, dP, dQ, qInv } } }`.

---

![alt text](<3. View pem.png>)

## 4. Nhập file PEM: public → n, e; private → n, e, d, ...

**Cách làm:** tab 2: Button `btnImport`, TextBox Multiline `txtParams`.

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
        sb.AppendLine("d    = " + Convert.ToHexString(p.D));
        sb.AppendLine("p    = " + Convert.ToHexString(p.P));
        sb.AppendLine("q    = " + Convert.ToHexString(p.Q));
        sb.AppendLine("dP   = " + Convert.ToHexString(p.DP));
        sb.AppendLine("dQ   = " + Convert.ToHexString(p.DQ));
        sb.AppendLine("qInv = " + Convert.ToHexString(p.InverseQ));
        privPem = text;
        pubPem = rsa.ExportSubjectPublicKeyInfoPem();
    }
    else pubPem = text;
    txtParams.Text = sb.ToString();
}
```

**Giải thích:**
- `ImportFromPem`: nạp khoá, tự nhận public hay private.
- `ExportParameters(false)` chỉ trả n, e; `ExportParameters(true)` trả đủ d, p, q... (chỉ được khi nạp private key).
- `RSAParameters`: `Modulus` = n, `Exponent` = e, `D` = d, `DP` = d mod (p−1), `DQ` = d mod (q−1), `InverseQ` = q⁻¹ mod p.
- `new BigInteger(bytes, true, true)` đổi mảng byte thành số lớn; e hiện ra `65537`.

![alt text](<4. file pem ( chứa đủ ).png>) 

![alt text](<4. file pem (n_e).png>)

**Kiểm tra:** nhập `public.pem` chỉ thấy n và e; nhập `private.pem` thấy thêm d, p, q, dP, dQ, qInv.

---

## 5. Mã hoá dữ liệu ≤ 190 byte bằng key vừa import, lưu Base64 ra file

**Cách làm:** tab 3: TextBox `txtData`, `txtCipher`, Button `btnEncrypt`.

```csharp
private void btnEncrypt_Click(object sender, EventArgs e)
{
    byte[] data = RandomNumberGenerator.GetBytes(32);        // ví dụ khoá AES-256 = 32 byte
    txtData.Text = Convert.ToBase64String(data);

    using var rsa = RSA.Create();
    rsa.ImportFromPem(pubPem);                               // chỉ cần PUBLIC key
    byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    string b64 = Convert.ToBase64String(cipher);
    txtCipher.Text = b64;
    File.WriteAllText(@"D:\cipher_base64.txt", b64);         // lưu file
}
```

**Giải thích:**
- 32 byte ngẫu nhiên = một khoá AES-256 (đúng ví dụ của đề), hiển thị Base64 44 ký tự.
- `OaepSHA256` là kiểu đệm quyết định giới hạn **190 byte**; vượt quá thì `Encrypt` ném `CryptographicException`.
- Bản mã RSA luôn dài đúng bằng khoá (2048 bit = 256 byte, Base64 khoảng 344 ký tự).
- Mã hoá cùng dữ liệu hai lần cho hai bản mã khác nhau (OAEP có phần ngẫu nhiên).

![alt text](<5. mã hóa dữ liệu.png>)

**Kiểm tra:** `txtCipher` hiện khoảng 344 ký tự; file `D:\cipher_base64.txt` có cùng nội dung.

---

## 6. Giải mã (đầu vào là PEM và file Base64), so sánh với nguồn

**Cách làm:** thêm Button `btnDecrypt`, TextBox `txtResult`:

```csharp
private void btnDecrypt_Click(object sender, EventArgs e)
{
    string priv = File.ReadAllText(@"D:\private.pem");
    string b64  = File.ReadAllText(@"D:\cipher_base64.txt").Trim();

    using var rsa = RSA.Create();
    rsa.ImportFromPem(priv);
    byte[] plain = rsa.Decrypt(Convert.FromBase64String(b64), RSAEncryptionPadding.OaepSHA256);

    byte[] original = Convert.FromBase64String(txtData.Text);
    txtResult.Text = plain.AsSpan().SequenceEqual(original)
        ? "GIỐNG dữ liệu gốc" : "KHÁC dữ liệu gốc";
}
```

**Giải thích:**
- Đầu vào đúng như đề: file PEM (private key) và file chứa dữ liệu mã hoá dạng Base64.
- Phải dùng **cùng kiểu đệm** `OaepSHA256` như lúc mã hoá.
- Giải mã cần **private key**; dùng khoá không cùng cặp sẽ lỗi.

![alt text](<6. so sánh dữ liệu đã mã hóa .png>)

**Kiểm tra:** kết quả "GIỐNG dữ liệu gốc".

---

## 7. Đánh giá tốc độ mã hoá, giải mã (e bé so với d to)

**Cách làm:** tab 4: Button `btnBench`, TextBox Multiline `txtBench`.

```csharp
private void btnBench_Click(object sender, EventArgs e)
{
    using var priv = RSA.Create(); priv.ImportFromPem(privPem);
    using var pub  = RSA.Create(); pub.ImportFromPem(pubPem);
    byte[] data = RandomNumberGenerator.GetBytes(32);
    byte[] enc  = pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);   // chạy khởi động
    int N = 500;

    var sw = Stopwatch.StartNew();
    for (int i = 0; i < N; i++) pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    double encMs = sw.Elapsed.TotalMilliseconds / N;

    sw.Restart();
    for (int i = 0; i < N; i++) priv.Decrypt(enc, RSAEncryptionPadding.OaepSHA256);
    double decMs = sw.Elapsed.TotalMilliseconds / N;

    txtBench.Text = $"Mã hoá (public, e = 65537): {encMs:F4} ms\r\n" +
                    $"Giải mã (private, d lớn): {decMs:F4} ms (chậm hơn {decMs / encMs:F1} lần)";
}
```

**Giải thích:**
- Một lần chỉ mất vài chục micro giây, quá ngắn để đo chính xác nên **lặp N = 500 lần** rồi lấy trung bình; chạy khởi động trước để loại thời gian khởi tạo lần đầu.
- Mã hoá dùng **e = 65537 (17 bit)** nên ít phép nhân; giải mã dùng **d cỡ 2048 bit** nên nhiều phép nhân hơn, vì vậy chậm hơn.

**Mở rộng:** lặp lại với khoá 1024, 2048, 3072, 4096 bit và ghi bảng:

| Độ dài khoá | Mã hoá (ms) | Giải mã (ms) | Giải mã / Mã hoá |
|---|---|---|---|
| 1024 | | | |
| 2048 | | | |
| 3072 | | | |
| 4096 | | | |

![alt text](<7. So sánh các độ dài khoá..png>) 

![alt text](<7. So sánh với khóa đang dùng.png>)

**Kết luận mẫu:** dùng private key (d lớn) chậm hơn nhiều lần so với public key (e bé); khoá càng dài càng an toàn nhưng càng chậm; sinh khoá là bước tốn thời gian nhất.

---

## 8. Giao diện sinh chuỗi băm SHA-256, đánh giá thay đổi khi đầu vào đổi rất ít

**Cách làm:** tab 5: TextBox `txtIn` (nhập), TextBox `txtHash` (kết quả), TextBox Multiline `txtHashLog`. Bấm đúp `txtIn` để tạo sự kiện `TextChanged`:

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

**Giải thích:**
- `TextChanged` chạy mỗi khi gõ hoặc xoá một ký tự nên băm cập nhật tức thì.
- SHA-256 luôn ra 256 bit = 32 byte = 64 ký tự hex, bất kể đầu vào dài hay ngắn.
- `h[i] ^ prevHash[i]` (XOR) cho bit 1 ở chỗ khác nhau; `PopCount` đếm số bit 1, tức số bit khác nhau giữa hai lần băm.
- `diff / 2.56` đổi số bit khác (trên 256) sang phần trăm.

![alt text](<8. dữ liệu ban đầu.png>)

 ![alt text](<8. thay đổi dữ liệu.png>)

**Kiểm tra và kết quả cho báo cáo:** gõ `hello` rồi đổi thành `hellp` (đổi 1 ký tự): khoảng **50%** số bit thay đổi. Đây là **hiệu ứng tuyết lở**. Cùng đầu vào luôn cho cùng kết quả; không thể suy ngược đầu vào từ giá trị băm.

---

## 9. Chữ ký số, và đề xuất để cùng dữ liệu + cùng người ký cho chữ ký khác nhau

**Nguyên lý chữ ký số:**
1. Người ký tính **băm SHA-256** của dữ liệu.
2. Dùng **private key** "mã hoá" giá trị băm ra chữ ký.
3. Người nhận dùng **public key** kiểm tra; khớp thì dữ liệu nguyên vẹn và đúng người ký.

Dữ liệu khác nhau thì băm khác nhau nên chữ ký khác nhau; sửa dữ liệu dù 1 ký tự thì chữ ký cũ hết hợp lệ.

**Cách làm:** tab 6: TextBox `txtSignData` (dữ liệu), TextBox Multiline `txtSignOut`, Button `btnSign`:

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
        sb.AppendLine($"PSS   lần {i}: {Convert.ToBase64String(s)[..40]}...  hợp lệ = {ok}");
    }
    txtSignOut.Text = sb.ToString();
}
```
**Giải thích:**
- `SignData(dữ liệu, SHA256, padding)`: tự băm bằng SHA-256 rồi ký bằng private key.
- `VerifyData(...)`: xác thực bằng public key, trả `true/false`; phải dùng **đúng cùng kiểu padding** khi ký và khi xác thực.
- `Pkcs1` (PKCS#1 v1.5): kiểu xác định, cùng dữ liệu và cùng khoá cho **chữ ký giống hệt** mỗi lần. Đây là điều đề muốn thay đổi.
- `Pss` (RSASSA-PSS): kiểu ngẫu nhiên hoá, mỗi lần ký ra chữ ký **khác nhau** nhưng đều hợp lệ.

![alt text](<9. chữ ký số.png>)

**Kết quả cần có:** 3 chữ ký PKCS1 giống nhau; 3 chữ ký PSS khác nhau, cả 3 `hợp lệ = True`.

**Đề xuất phương pháp:**
1. **RSASSA-PSS (khuyên dùng).** Mỗi lần ký sinh một **salt ngẫu nhiên**, ghép với giá trị băm rồi băm tiếp và che bằng MGF1 để tạo khối dữ liệu đem đi luỹ thừa bằng private key. Salt khác thì khối khác, nên chữ ký khác. Salt nằm sẵn trong chữ ký nên người nhận khôi phục và xác thực được bằng public key, không cần gửi thêm gì.
2. **Ghép nonce.** Sinh nonce ngẫu nhiên (hoặc dấu thời gian), ký `H(dữ liệu ‖ nonce)`, rồi gửi kèm `(dữ liệu, nonce, chữ ký)`. Nhược điểm: phải truyền thêm nonce.

**Lợi ích:** chữ ký không lặp lại nên không bị theo dõi hay so khớp; PSS có chứng minh an toàn chặt chẽ hơn PKCS#1 v1.5.

---


