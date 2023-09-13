## Daftar Isi Pembahasan Hari Kedua

- [Session Hijacking](#session-hijacking)
- [Cross Site Scripting](#sql-injection)
- [Cross Site Request Forgery](#directory-traversal-vulnerabilities)
- [Man In The Middle](#directory-traversal-vulnerabilities)
- [Man In The Browser](#directory-traversal-vulnerabilities)
- [Insecure Direct Object Reference](#file-inclusion-vulnerabilities)

## Session Hijacking

### Deskripsi
Session hijacking adalah ketika seseorang jahat mencoba mencuri akses ke akun atau informasi online kita dengan cara meretas atau mencuri kode khusus yang digunakan untuk mengidentifikasi kita sebagai pengguna yang sah. Dengan kode ini, mereka bisa mengendalikan akun kita dan melakukan hal-hal yang tidak baik, seperti mencuri data pribadi.

### Metode

- [Physical Access](#physical-access)
- [Session Sidejacking](#session-sidejacking)
- [Session Fixation](#session-fixation)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
<br>

### Physical Access

Physical access adalah akses fisik atau langsung ke perangkat keras atau tempat di mana data atau sistem komputer tersimpan. Ini berarti seseorang memiliki fisik akses ke perangkat, seperti komputer, server, atau perangkat penyimpanan, dan dapat memanipulasi atau mencuri informasi darinya. 

### Session Sidejacking

Session sidejacking adalah serangan yang terjadi ketika seorang penyerang berhasil mencuri atau mengakses cookie otentikasi dari komputer atau perangkat pengguna yang sah. Cookie adalah potongan kecil data yang disimpan pada perangkat pengguna oleh situs web atau aplikasi untuk mengidentifikasi pengguna yang sah selama sesi online mereka. Dengan mengambil cookie ini, penyerang dapat "mengkloning" sesi pengguna yang sah dan mendapatkan akses yang tidak sah ke akun atau layanan online tersebut.

![image](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/2e0e9d02-65e6-4a06-ab7f-96ecc66946c3)
<br>

### Session Fixation

Session fixation adalah jenis serangan keamanan yang dilakukan dengan cara memanipulasi atau menetapkan ID sesi (session ID) pengguna pada suatu situs web atau aplikasi sebelum pengguna melakukan login atau sesi awal mereka. Penyerang mencoba memaksa pengguna untuk menggunakan ID sesi yang telah mereka tetapkan, yang memungkinkan penyerang untuk mengendalikan atau memonitor sesi pengguna tersebut. Ini dapat digunakan untuk mendapatkan akses tanpa izin ke akun pengguna atau untuk mencuri data pribadi mereka selama sesi. 

![image](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/b1f54ade-6c7e-43c5-9a74-bc8a458ff767)
<br>

### Pencegahan Session Hijacking

- Penggunaan Secure dan HTTPOnly Flags pada Cookies
  
Memastikan bahwa cookie yang berisi informasi sesi hanya dikirimkan melalui koneksi HTTPS yang aman dan tidak dapat diakses oleh JavaScript dapat membantu melindungi sesi pengguna dari serangan XSS dan serangan man-in-the-middle.

- Penggunaan HTTPS

Menggunakan koneksi HTTPS yang aman adalah langkah kunci dalam melindungi sesi pengguna. Ini mengenkripsi data yang dikirimkan antara server dan peramban pengguna, mengurangi risiko peretasan sesi.

- Pola Nama dan Nilai Cookie yang Acak

Gunakan nama cookie yang sulit ditebak dan nilai yang unik untuk mengurangi risiko serangan session hijacking. Ini membuat lebih sulit bagi penyerang untuk menebak atau menebak cookie sesi pengguna.



## Cross-Site Scripting (XSS)

### Deskripsi

Cross-Site Scripting (XSS) adalah serangan keamanan pada aplikasi web di mana penyerang menyisipkan kode berbahaya ke dalam halaman web yang kemudian akan dieksekusi oleh pengguna yang mengunjungi halaman tersebut. Serangan ini memanfaatkan kurangnya sanitasi atau validasi data yang masuk ke dalam aplikasi web, dan ketika kode berbahaya dieksekusi, penyerang dapat mencuri data pengguna, mengendalikan sesi pengguna, atau merusak tampilan dan fungsionalitas halaman web.

### Jenis

#### Stored XSS

Serangan di mana skrip berbahaya disimpan di server dan dieksekusi ketika pengguna mengakses halaman dengan data tersebut (misalnya, dalam posting forum).

#### Reflected XSS

Serangan di mana skrip berbahaya disertakan dalam permintaan atau tautan yang diberikan kepada korban dan dieksekusi saat korban mengakses tautan atau merespons permintaan tersebut. Serangan ini tidak disimpan di server.


### Identifikasi Kerentanan XSS

- Terjadi ketika sebuah situs web tidak memeriksa data yang dimasukkan oleh pengguna dengan benar sebelum menampilkannya di halaman web.
- Contoh input yang berpotensi berbahaya termasuk karakter khusus seperti `<, >, ', ", {, }, dan ;`. Jika input ini tidak diolah dengan benar, mereka dapat digunakan oleh penyerang untuk menjalankan skrip berbahaya pada peramban pengguna lain.
  
### Contoh Serangan

- Menampilkan Alert Window
Dalam contoh ini, kode disisipkan dalam input pada halaman web. Ketika halaman itu dimuat oleh pengguna lain, alert window dengan pesan "1" akan muncul di peramban mereka. Ini adalah contoh dari serangan XSS yang sederhana.
```
<script>alert(1)</script>
```
- Mencuri Cookies
Dalam contoh ini, kode digunakan untuk mencuri informasi cookie pengguna. Ketika kode ini dieksekusi, jendela peringatan akan muncul dengan daftar cookie pengguna. Penyerang dapat mengambil informasi ini untuk mengakses akun pengguna.
```
<script>alert(document.cookie)</script>
```
- Mengarahkan ke Website Lain
Di sini, kode digunakan untuk mengarahkan pengguna ke situs web Google. Penyerang dapat memanfaatkan ini untuk mengalihkan pengguna ke situs jahat yang mungkin berisi serangan lebih lanjut.
```
<script>window.location='http://www.google.com'</script>
```

### Efek Dari XSS

1. Pencurian Data Sensitif 

2. Mengubah Tampilan dan Isi Dari Website

3. Pemasangan Trojan Horse

4. Mengarahkan Pengguna ke Situs Jahat

### Pencegahan XSS

- Penggunaan htmlentities() PHP Function

Fungsi `htmlentities()` dalam PHP digunakan untuk mengonversi karakter khusus ke dalam entitas HTML sehingga mereka tidak diinterpretasikan sebagai kode HTML atau JavaScript yang berbahaya. Ini membantu dalam mencegah XSS.
```
$input = '<script>alert("XSS Attack")</script>';
$output = htmlentities($input, ENT_QUOTES, 'UTF-8');
echo $output;
// Hasilnya: &lt;script&gt;alert(&quot;XSS Attack&quot;)&lt;/script&gt;
```

- Penggunaan xss_clean() CodeIgniter Function

CodeIgniter adalah kerangka kerja PHP yang memiliki fungsi bawaan `xss_clean()` yang digunakan untuk membersihkan data input dari potensi skrip berbahaya sebelum digunakan atau disimpan dalam database.
```
$data = $this->input->post('input_data');
$clean_data = $this->security->xss_clean($data);
```

- Penggunaan Laravel

Dalam Laravel, sanitasi data dan melindungi dari XSS dapat dicapai dengan berbagai cara, termasuk oleh fitur yang disediakan oleh Laravel sendiri dan dengan menggunakan Blade, mesin template Laravel, yang secara otomatis menghindari XSS.
```
<p>{!! $user_input !!}</p>
```

- Menggunakan if Statement pada CodeIgniter

Pernyataan ini digunakan untuk memeriksa apakah hasil dari `xss_clean()` dalam CodeIgniter mengembalikan `TRUE atau FALSE`. Jika mengembalikan TRUE, itu berarti data mengandung potensi XSS.
```
$file = $this->input->post('file_data');
if ($this->security->xss_clean($file, TRUE) === FALSE) {
    // Data berpotensi XSS
} else {
    // Data aman
}
```

### Penyerangan Dengan DVWA dan XSS

#### Set Up
Penyerangan ini dilakukan dengan DVWA dalam docker. Untuk insialisasinya sebagai berikut:

1. Pastikan docker version adalah 23.0.5 atau terbaru
2. Clone atau download link berikut https://github.com/digininja/DVWA
3. Open terminal dan masuk ke dalam directory DVWA
4. Lakukan run `docker compose up -d`
5. Masuk ke dalam `http://localhost:4280`

#### Langkah - Langkah Penyerangan
1. Saat masuk ke dalam `localhost:4280`, tampilan DVWA akan terlihat seperti berikut.
   ![Screenshot from 2023-09-13 18-41-38](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/442365a1-feea-4676-812e-2e8296ed80ef)
2. Masukkan username, yaitu `admin` dan passwordnya adalah `password`
3. Set up database dengan melakukan klik pada `Create/Reset Database`   
   ![Screenshot from 2023-09-13 18-56-38](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/f69d9871-cb9d-411f-89de-9df36bd2c2fe)
4. Setelah itu, pastikan bahwa tingkat kesulitan adalah `Low` dengan cara masuk ke dalam opsi bar `DVWA Security`
   ![Screenshot from 2023-09-13 18-42-11](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/7bde1b96-54dd-456e-8012-d235b862ddd5)
6. Selanjutnya, pergi ke dalam opsi bar `XSS (Reflected)`. Pada percobaan pertama, diketikkan tulisan "test" pada kolom di samping "What's your name?" dan diikuti klik tombol submit. Hasil dari proses tersebut adalah `Hello test`
   ![Screenshot from 2023-09-13 18-42-45](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/d534a702-de6c-4870-872e-bbf38d8b9ba7)
7. Pada percobaam kedua, dilakukan penyerangan pada DVWA dengan melakukan pengetikan berupa
   ```
   <script>alert("XSS Challenge")</script>
   ```
   pada kolom di samping "What's your name?" dan diikuti klik tombol submit, dan terjadi hasil seperti berikut
   ![Screenshot from 2023-09-13 18-43-11](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/39cb7a28-efc4-42f2-ba11-45d322414da8)
<br>
<br>

Dari contoh di atas, dapat diketahui serangan XSS kecil yang menampilkan alert window dalam mode low. Untuk selanjutnya merupakan contoh penyerangan dalam mode medium. Langkah - langkah dari penyerangan ini sama seperti pada mode low, namun ada sedikit perbedaan seperti mengubah pengaturan tingkat modenya dari low menjadi medium dan contoh penyerangannya. Berikut merupakan detail dari perbedaan tersebut:

1. Tingkat kesulitan diganti menjadi `medium` pada opsi bar `DVWA Security`
   ![Screenshot from 2023-09-13 18-43-36](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/f34effbd-0b28-4a18-aa97-c3bee471c5fd)
2. Lalu pada opsi bar `XSS (Reflected)`, masukkan code untuk penyerangan. Dalam hal ini diketikkan code seperti di bawah ini untuk melakukan penyerangan
   ```
   <img src="x" onerror="alert('XSS Medium')">
   ```
   ![Screenshot from 2023-09-13 18-56-49](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/943120b2-05ca-4cde-a665-d787c2f1fb2c)
3. Setelah itu, klik tombol `submit` dan akan keluar hasil seperti berikut
   ![Screenshot from 2023-09-13 18-43-59](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/110476969/646840ad-60e1-4c1e-9403-8f653b9aa6fd)

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
  
### Serangan di DVWA dengan security level medium

> Disini, kita gunakan OS Kali Linux  
> Task: Membuat current user untuk mengubah password tanpa mereka ketahui. Untuk menembus proteksi pengecekan referer, maka jebakan script harus attacker tanam di website tersebut. Apabila hal tersebut berhasil, maka attacker memiliki referer ke DVWA>  

Cara:
1. Kita aktifkan dulu `apache2` dan `mysql` pada kali linux
    <img width="213" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/c8f21ed8-30fe-47d1-ae95-38e98e55f33b">

2. Kita masuk ke website dvwa dengan url `http://127.0.0.1/DVWA/login.php`
    <img width="380" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/4bd672bf-40d1-4a5d-bd80-a706a7745a66">

3. Kita lakukan login dengan `username: admin` dan `password: password`

    <img width="793" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/ade9d7b1-f53a-4035-83dc-fdd0c7eca538">

4. Kita set `security level: medium`
    <img width="446" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/ef60ec50-6b95-4e12-86a4-51ae366dc703">

5. Kita masuk ke tab `CSRF`

   <img width="562" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/095328a2-7314-4330-8f38-7e3087f869dd">

6. Kita bedah source codenya:
   ![4](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/a3010f58-f6b7-4154-976f-e645263b81a8)

    * Jadi, saat button `Change` di klik, maka method `GET` akan bekerja. Disini, terdapat if else condition.
    * Dalam If else condition tersebut, kita gunakan fungsi php `stripos()` untuk mencari substring dalam sebuah string. Kita cek substring dari `HTTP_REFERER` apakah sama dengan substring dari `SERVER_NAME` yang sesuai.
    * HTTP REFERER: Berisi URL halaman sebelumnya yang mengarah ke halaman saat ini. 
    * `SERVER_NAME` yang sesuai dapat kita cek dari `PHP Info`
      <img width="634" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/d5d5af96-fa7a-4e73-bce9-591f1f604813">

7. Untuk melakukan attack, kita gunakan user lain. Misal, kita gunakan `User: pablo` dengan `password: letmein`

    * Dengan user `pablo`, kita menuju tab `XSS (Stored)`
      <img width="480" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/1355a446-f080-41cc-8b39-77ef2d794399">

    * Disini, kita lakukan inspect element pada input text dari `name` lalu kita hapus `MAX_LENGTH`
        <img width="635" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/03c0540b-e2f7-4aba-adf9-21cb3e9d5eb6">

    * Kita masukkan syntax ini di dalam input text dari `Name`
      ```
      <img src="/DVWA/vulnerabilities/csrf/?password_new=hack&password_conf=hack&Change=Change#">
      ```
    * Lalu, kita masukkan message berupa "Message"
      <img width="340" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/6c1ec92e-e070-4db3-9610-258c3d16859d">

    * Setelah itu, kita klik button `Sign Guestbook`
        <img width="339" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/3f5992a0-319a-4fec-bffb-c960605aafe7">

8. Kita kembali ke `user: admin` dengan `password: password`
   * Disini, kita dapat terkena attack ketika kita masuk ke tab `XSS (Stored)`  
     <img width="460" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/ff124e49-236e-47c2-a5ac-2290a4fa5fae">
   * Lalu, kita masuk ke tab `CSRF`. Apabila kita cek kredensial dengan `user: admin` dan `password: password`, maka hasilnya:
     <img width="302" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/c7785516-4ba1-4f59-8bc3-a0df9589492b">
   * Apabila kita masukkan password dengan password yang telah diubah dengan user pablo yaitu `password: hack`, maka:
     <img width="305" alt="image" src="https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/91377782/46074200-4f09-4eaf-8212-7f4b4bb337c1"> 

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

