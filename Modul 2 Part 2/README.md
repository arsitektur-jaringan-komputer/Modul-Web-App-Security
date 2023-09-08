![image](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/107338432/977f04db-1317-4e32-bb37-3c8f36c1c706)# Modul 2 Part 2 Web App Security

## Man-in-the-middle Attack

![WhatsApp Image 2023-09-05 at 7 25 30 PM](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/107338432/9606e60d-0b1b-4545-9146-77b3a433cda4)

Man in the Middle Attack, atau dapat disingkat MitM, adalah salah satu jenis _cyber attack_ yang bekerja dengan cara 'menyusup' ke dalam jaringan dan menyadap komunikasi yang sedang berlangsung antara pengguna jaringan dan web server tujuan.

Serangan ini dapat dilakukan dengan cara-cara sebagai berikut:

1. Menggunakan arpspoof tool.

```
arpspoof –i <interface> -t <victim IP> <router IP>
```

2. Rekam lalu lintas jaringan menggunakan Wireshark.

Lantas, bagaimana kita tau bahwa kita telah menjadi korban MitM? Beberapa hal yang dapat kita lakukan untuk mengetahuinya adalah sebagai berikut:

1. Cari respons paket ARP yang tidak biasa.
2. Biasanya, banyak lompatan antara paket masuk dan keluar berbeda.
3. Gunakan HTTPS.

## Man-in-the-browser Attack

Man-in-the-browser (MitB) memiliki pendekatan yang sama dengan MitM. Namun, dalam MitB, _Trojan Horse_ digunakan untuk menyusup dan memanipulasi panggilan antara aplikasi utama yang dapat dijalankan (misal browsernya) dan mekanisme keamanannya maupun library-nya secara langsung.

Berikut adalah beberapa cara yang dapat dilakukan untuk menghindari serangan MitB:

1. Jangan meng-_install_ ekstensi browser yang tidak terverifikasi.
2. Jangan meng-_install_ DLL, driver, maupun aplikasi yang tidak terverifikasi.

#BUAT PT2.1

### Blind SQL Injection

Blind SQL Injection adalah jenis serangan SQL Injection yang mengajukan pertanyaan-pertanyaan true or false kepada database dan menentukan jawabannya berdasarkan respons aplikasi.

Berikut adalah beberapa metode dari Blind SQL Injection:

1. Union Exploitation
2. Boolean Exploitation
3. Time Delay Exploitation
4. Error-based Exploitation
5. Out of Band Exploitation
6. Stored Procedure Injection

### Union Exploitation

Operasi UNION digunakan dalam SQL Injection untuk menggabungkan hasil dari dua atau lebih query SQL dalam satu hasil yang dikembalikan oleh aplikasi web. Dengan memasukkan UNION SQL yang benar, penyerang dapat mencoba menggabungkan hasil dari query yang dieksekusi dengan hasil dari query tambahan yang mereka tentukan. Hasilnya adalah penyerang dapat melihat data yang seharusnya tidak mereka akses, seperti informasi pengguna, kata sandi, atau data sensitif lainnya yang disimpan dalam database.

Contoh query:

``` sql
SELECT Name, Phone, Address FROM Users WHERE Id=$id

-- Set $id to:
-- 1 UNION ALL SELECT creditCardNumber,1,1 FROM CreditCardTable
```

Perlu diingat bahwa kata kunci 'ALL' digunakan untuk menggantikan 'DISTINCT' dan bahwa jumlah kolom dalam kedua bagian query harus sama.

### Boolean Exploitation

Ekploitasi berbasis boolean mengacu pada penggunaan eksploitasi atau manipulasi operasi logika boolean dalam sebuah aplikasi atau sistem.

Contoh query:

```sql
SELECT field1, field2, field3 FROM Users WHERE Id='$Id’

-- Set $id to:
-- 1' AND '1'='2
-- Or,
-- 1' AND ASCII(SUBSTRING(username,1,1))=97 AND '1'='1
```

### Time-based SQL Injection

SQL Injection jenis ini dilakukan dengan mengirimkan input berbahaya ke aplikasi web untuk mencari tahu informasi tentang basis data berdasarkan waktu yang diperlukan untuk merespons permintaan. Tujuannya adalah untuk mengungkapkan informasi rahasia dari basis data secara bertahap, terutama jika aplikasi tidak memberikan respons langsung yang menunjukkan adanya kerentanan SQL Injection.

Contoh query:

``` sql
SELECT * FROM products WHERE id_product=$id_product

-- Set $id_product to:
-- 10 AND IF(version() like ‘5%’, sleep(10), ‘false’))--
```

Lantas, bagaimana cara mengidentifikasi kelemahan SQL Injection? Terdapat hal-hal yang dapat dilakukan, di antaranya mencari parameter, cookies, maupun header HTML yang dapat diedit. Selain itu, dapat digunakan _tool_ seperti SQLMap.

Berikut adalah beberapa pencegahan SQL Injection.

1. Hindari input oleh pengguna.

``` php
$id = $_POST[ 'id' ];

$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

2. Gunakan statements yang telah disiapkan sebelumnya.

``` php
// was a number entered?
if(is_numeric( $id )) {
  // check the database
  $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
  $data->bindParam( ':id', $id, PD0::PARAM_INT );
  $data->execute();
  $row = $data->fetch();

  // make sure only 1 result is returned
  if( $data->rowCount() == 1 ) {
    // get values
    $first = $row[ 'first_name' ];
    $last = $row[ 'last_name' ];

    // feedback for end user
    echo "<pre>ID: {$id}<br />First name: {$first)<br />Surname: {$last}</pre>";
  }
}
```

``` php
$someVariable = Input::get("some_variable");

$results = DB::select( DB::raw("SELECT * FROM some_table WHERE some_col = :somevariable"), array('
  somevariable' => $someVariable,
 ));
```

3. Gunakan _stored procedures_.
4. Pastikan pengguna database memiliki _privilege requirement_ seminimum mungkin.
5. Gunakan _whitelist_ untuk validasi input.
