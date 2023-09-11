# Modul 2 Part 1 Web App Security

## Cross Site Request Forgery 

### Deskripsi
Cross Site Request Forgery merupakan suatu serangan yang memaksa end user untuk melakukan tindakan yang tidak mereka sadari pada web di mana mereka saat ini sudah terautentikasi (bisa berupa login dengan akun user dan kata sandi atau metode autentikasi lainnya)

### Cara kerja serangan:
1. Dalam GET Scenario:
    - Craft a fake URL:  
    Penyerang menyusun sebuah URL (Uniform Resource Locator) dengan tujuan tertentu untuk membuat korban mengklik link URL tersebut. URL yang dibuat merupakan URL palsu dengan tujuan memanipulasi korban yang dapat menguntungkan pelaku. 
    - Craft a fake image  
    Penyerang dapat mengirimkan fake image ke user yang telah terautentikasi dan image tersebut mengandung kode atau tindakan yang dapat membahayakan user tersebut. Akibatnya, ketika pengguna membuka gambar tersebut, penyerang akan menjalankan tindakan berbahaya tanpa sepengetahuan user. 

2. Dalam POST Scenario:
    - Create a fake (hidden) form:  
    Penyerang membuat beberapa form palsu ataupun form tersembunyi. Contoh aksi yang dilakukan penyerang yaitu aksi pengiriman form ke suatu bank untuk melakukan transfer.
Berikut contoh kodenya:
        ``` Volt
        <form action="http://bank.com/transfer.do" method="POST">
        <input type="hidden" name="acct" value="MARIA"/>
        <input type="hidden" name="amount" value="100000"/>
        <input type="submit" value="View my pictures"/>
        </form>
        ```
### Cara protect websites dari CSRF
1. Menggunakan secret cookie:
   * Kita dapat melindungi situs web dari serangan CSRF dengan menggunakan "Token CSRF"
   * Token CSRF adalah token unik yang dihasilkan oleh server dan disematkan dalam cookie atau dalam tag input tersembunyi dalam form.
   * Token CSRF berperan sebagai "tanda pengenal" yang dikirimkan bersamaan dengan permintaan HTTP dari user. Server kemudian akan memeriksa apakah token tersebut cocok dengan yang diharapkan. Jika tidak cocok atau tidak ada token, maka server akan menolak permintaan tersebut. 
2. Hanya menerima POST requests:
   * Cara lain untuk melindungi situs web dari serangan CSRF adalah dengan hanya mengizinkan operasi yang dapat mengubah data atau status server untuk menggunakan permintaan HTTP POST.
   * POST requests ini dapat membuat penyerang kesulitan untuk memanipulasi tindakan karena tidak bisa mengirimkan permintaan dari situs web yang dikendalikan.
3. Multi-step transactions:
   * Kita dapat memberikan aturan lapisan tambahan keamanan untuk berbagai aksi yang dijalankan oleh user.
   * Contoh:
     Saat user ingin mengubah kata sandi, sistem meminta mereka untuk memasukkan kata sandi saat ini sebelum memperbolehkan mereka untuk membuat perubahan. 
     
4. Menggunakan HTTPS:
   * HTTPS menyediakan enkripsi lalu lintas data antara klien dan server, sehingga sulit bagi penyerang untuk memanipulasi atau membaca data yang ditransfer.
   * HTTPS juga membantu memastikan integritas data yang dikirimkan antara pengguna dan server

### Serangan di DVWA dengan security level low

> Disini, kita gunakan OS Kali Linux
> Task: Membuat current user untuk mengubah password tanpa mereka ketahui

Cara:
1. Kita aktifkan dulu `apache2` dan `mysql` pada kali linux
    <img width="213" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/c8f21ed8-30fe-47d1-ae95-38e98e55f33b">

2. Kita masuk ke website dvwa dengan url `http://127.0.0.1/DVWA/login.php`
    <img width="380" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/4bd672bf-40d1-4a5d-bd80-a706a7745a66">

3. Kita lakukan login dengan `username: admin` dan `password: password`

    <img width="793" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/ade9d7b1-f53a-4035-83dc-fdd0c7eca538">

4. Kita set `security level: low`

   <img width="478" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/725b04eb-5f97-407f-aac8-b0e50ad975dc">

5. Kita masuk ke tab `CSRF`

   <img width="562" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/095328a2-7314-4330-8f38-7e3087f869dd">

6. Disini, kita dapat mengubah password dari current user secara diam-diam dengan memasukkan password baru di `new password` dan konfirmasi di `confirm new password`. Awalnya, password dari user `admin` adalah `password`. Kita coba ubah passwordnya menjadi `123`

   <img width="225" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/3e2c6e24-faec-4904-a107-5e344244f7f9">

7. Saat kita klik tombol change, maka password otomatis keubah. Hal ini dapat kita lihat dari `Test Credentials`

   <img width="184" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/5266dfa0-5747-4f41-bdbb-51ba1c6f1237">

    <img width="195" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/83ea379e-2a4b-40d1-9888-028a852ba9ce">

8. Hal ini dapat terjadi karena ada beberapa kerentanan. Mari kita bedah satu per satu:  
   a. Kerentanan dari source code saat klik `Change`
        ![csrf](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/7c4d5694-7bcd-4084-a639-9de5e1e78888)

   * Dari kode tersebut, dapat kita lihat bahwa memakai method `GET` yang berarti data dikirim melalui URL.
   * Dari kode tersebut juga, kita dapat langsung melakukan update ketika `new password == configurasi password` yang berarti tidak ada security tambahan untuk mengecek kredensial tersebut

   b. Kerentanan dari url akibat method `GET`  
       <img width="476" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/7ea367f9-e391-4ddf-89c3-a4e46450877d">
       
   * Dari link `http://127.0.0.1/DVWA/vulnerabilities/csrf/?password_new=123&password_conf=123&Change=Change#` maka web akan auto update password pada current user.
    
## SQL Injection

### Deskripsi
Suatu serangan SQL Injection terdiri dari penyisipan atau injeksi dari SQL query melalui input data dari klien ke aplikasi. Input data biasanya merujuk pada informasi yang diberikan oleh user melalui formulir web, parameter URL, atau inputan lainnya. 

### Dampak
Jika serangan SQL Injection ini berhasil, penyerang dapat memengaruhi atau memanipulasi operasi basis data yang dilakukan oleh aplikasi. Hal ini dapat mengakibatkan akses tidak sah ke data sensitif, perusakan atau modifikasi data, dan menjalankan eksekusi perintah SQL yang berpotensi merusak. 

### Contoh SQL Injection

``` Volt
”SELECT * FROM Users WHERE user='" . $user . "'" and pass='" . $pass . “’”
```
Syntax tersebut digunakan untuk melakukan query ke sebuah tabel Users dalam suatu database dengan tujuan untuk mengambil data pengguna yang cocokd engan kombinasi nama pengguna (user) dan kata sandi (pass) yang diberikan. 

### Hal-hal yang dapat dilakukan oleh penyerang dengan SQL Injection
1. Membaca data sensitif
   * Jika SQL Injection attack berhasil, penyerang dapat membaca atau mengakses data sensitif yang tersimpan dalam database
   * Data sensitif yang dapat diakses yaitu informasi pribadi pengguna seperti nama, alamat email, kata sandi terenkripsi, nomor kartu kredit, dan lain-lain.
2. Memodifikasi data
   * Penyerang dapat memanipulasi data yang ada dalam database dengan menyisipkan perintah SQL yang sesuai. Mereka dapat mengubah atau bahkan menghapus data yang ada dalam database. 
3. Eksekusi perintah tingkat admin di basis data
   * Serangan SQL Injection dapat memberikan penyerang berupa akses untuk menjalankan perintah SQL yang memiliki hak istimewa tingkat admin atau mengendalikan  basis data. 
4. Eksekusi perintah shell
   * Dalam beberapa kasus, jika sistem basis data dikonfigurasi dengan cara yang tidak aman atau jika penyerang memiliki pengetahuan tambahan tentang konfigurasi server, mereka dapat mencoba menjalankan perintah shell atau perintah sistem operasi yang dapat memberikan akses ke sistem yang lebih luas.
5. Membaca files
   * Dalam beberapa kasus, serangan SQL Injection dapat memungkinkan penyerang untuk membaca file di server yang mungkin berisi informasi sensitif, seperti file konfigurasi, file log, atau bahkan kode sumber aplikasi. 

### Cara identifikasi kerentanan web terhadap SQL Injection
1. Mencari input atau parameter apapun yang mungkin berinteraksi dengan basis data, termasuk header HTTP dan cookie:
   * Disini, kita harus melihat semua input dan parameter yang digunakan dalam aplikasi web, termasuk formulir, URL, parameter permintaan HTTP, header HTTP, dan data cookie
   * Kita juga harus perhatikan input apapun yang digunakan dalam query SQL atau operasi basis data
2. Memasukkan quotes atau semicolons sebagai nilainya
   * Penyerang sering mencoba memasukkan karakter seperti tanda kutip tunggal ('), tanda kutip ganda ("), atau titik koma (;) ke dalam input untuk melihat apakah aplikasi merespons kesalahan atau perilaku yang tidak diharapkan. Jika aplikasi web memberikan pesan kesalahan atau tidak berfungsi dengan benar saat karakter dimasukkan, maka termasuk indikasi kerentanan SQL Injection
3. Menggunakan tanda komentar di akhir jika diperlukan (#, --, /**/)
   * Penyerang sering mencoba mengakhiri pernyataan SQL yang sah dengan tanda komentar seperti "#" (Untuk MySQL), "--" (untuk banyak basis data), "/**/" (Untuk beberapa basis data)
   * Hal tersebut bertujuan untuk menghentikan kueri yang sah dan menyisipkan perintah SQL yang berbahaya
4. Mencari pesan error
   * Kesalahan yang diberikan oleh aplikasi web dapat memberikan petunjuk tentang kerentanan SQL Injection.
  
#### Pesan dari Error messages yang dapat kita ambil
![image](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/16a49d95-5b58-4fe4-9fa3-7364fc02eeeb)

* Masing-masing DBMS (Database Management System) memiliki error messages yang unik
* Mengenal DBMS yang digunakan membuat penyerang memiliki kemampuan untuk menyesuaikan serangan secara khusus ke DBMS tersebut.
* Cara mencegah serangan ke DBMS dari error messages:
  - Menyembunyikan error messages dari users

### Serangan di DVWA dengan security level low

> Disini, kita gunakan OS Kali Linux
> Task: Curi password dari users yang terdapat dalam database DVWA dengan menggunakan sql. Total users dalam database adalah 5 users dengan id dari 1 hingga 5.

Cara: 
1. Kita aktifkan dulu `apache2` dan `mysql` pada kali linux
    <img width="213" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/c8f21ed8-30fe-47d1-ae95-38e98e55f33b">

2. Kita masuk ke website dvwa dengan url `http://127.0.0.1/DVWA/login.php`
    <img width="380" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/4bd672bf-40d1-4a5d-bd80-a706a7745a66">

3. Kita lakukan login dengan `username: admin` dan `password: password`

    <img width="793" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/ade9d7b1-f53a-4035-83dc-fdd0c7eca538">

4. Kita set `security level: low`

   <img width="478" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/725b04eb-5f97-407f-aac8-b0e50ad975dc">

5. Kita masuk ke tab `SQL Injection`

   <img width="549" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/d5b47694-f22d-4ac1-a339-3ac96608b603">

6. Saat kita masukkan salah satu id, misal `id = 1`, maka akan terlihat seperti ini:
    <img width="283" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/f75e7b39-62da-409b-b39d-1b4e65f4aba6">

7. Kita bedah source codenya:

   ![sql_injection](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/a28209da-ad4d-4c26-827e-ac6beb532da2)

* Dari kode tersebut, apapun yang kita inputkan akan masuk menjadi query dan akan diproses. Sebab, isi dari variabel query:

  ```
  $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
  ```
* Untuk mendapatkan password, kita gunakan syntax `union` untuk mengambil password dari `id = 1`

  ``` SELECT first_name, last_name FROM users WHERE user_id = '1' UNION SELECT password, null FROM users -- '; ```

* Setelah itu, kita masukkan ke text input `User ID`
  `1' UNION SELECT password, null FROM users -- '; ``` `

  Disini, attacker memasukkan syntax tersembunyi yang dibuat menjadi comment yaitu `' UNION SELECT password, null FROM users -- '; `` `. Sehingga, apabila web rentan, maka union tidak akan terdeteksi.

8. Hasil serangan:
   <img width="398" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/a66c2bd3-32c0-47a5-aacf-245a7c602306">

9. Password tersebut dibuat dengan hashcode sehingga kita dapat generate hashcode tersebut di `crackstation.net`

    <img width="557" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/caae5d84-6c7f-4565-b203-c8ab648bba77">

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
