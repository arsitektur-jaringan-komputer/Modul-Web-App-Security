# Modul 1 Part 1 Web App Security

- [Directory Traversal Vulnerabilities](#directory-traversal-vulnerabilities)
- [File Inclusion Vulnerabilities](#file-inclusion-vulnerabilities)
- [Session Hijacking](#session-hijacking)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)

## Directory Traversal Vulnerabilities

### Deskripsi

Directory Traversal merupakan kerentanan dimana aplikasi web memperbolehkan client untuk mengakses file yang tidak seharusnya diakses dan tidak sewajarnya diakses melalui interface web diluar root directory website. Sebagai contoh, client dapat mengakses informsi/dokumen pada server yang seharusnya tidak ditampilkan di website.

### Contoh:

Kode php dan html dibawah, berfungsi sebagai pengubah warna background dari website kita dengan memberikan kode php berdasarkan warna yang dipilih pada parameter COLOR di GET request.
<br>
<br>

![image](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/100863813/82ed8a67-ee1b-4b92-958f-5291d4c0b395)

<br>
<br>

Menurut anda, apa yang akan anda lakukan sebagai penyerang untuk dapat mengakses file lain yang ada pada server?

### Cara Mengidentifikasi Kerentanan Directory Traversal

- Identifikasi request parameter yang dapat dimanipulasi
- Lakukan percobaan dengan memasukkan payload supaya website memuat informasi yang tidak seharusnya bisa diakses

## File Inclusion Vulnerabilities

### Deskripsi

File Inclusion merupakan kerentanan dimana user dapat mengeksekusi konten pada suatu file di website. File ini seharusnya tidak dapat dieksekusi secara bebas oleh user, namun dikarenakan kurang baiknya implementasi keamanan pada website, user jadi bisa mengeksekusi file tersebut.

### Jenis-Jenis Kerentanan File Inclusion

- [Local File Inclusion](#local-file-inclusion)
- [Remote File Inclusion](#remote-file-inclusion)
<br>
<br>

![image](https://github.com/arsitektur-jaringan-komputer/Modul-Web-App-Security/assets/100863813/e5f2a184-4a05-4893-b4fa-44e1f565cc36)


### Local File Inclusion

Local File Inclusion adalah kelemahan dimana user dapat mengeksekusi kontek file yang terletak pada server yang sama dengan website. Biasanya pada kasus LFI, seorang penyerang berhasil memasukkan sebuah file atau kode berbahaya melalui server atau website, lalu dengan memanfaatkan kerentanan File Inclusion, penyerang dapat mengeksekusi file tersebut pada website. Dampak pada sisi user yang dijadikan target adalah, penyerang bisa saja mengarahkan user ke lokasi file berbahaya yang telah disiapkan untuk menyerang user pada server, dan ketika user mengakses lokasi tersebut, user secara tidak sadar telah mengeksekusi file berbahaya yang telah disiapkan. Pemanfaatan yang paling umum terjadi pada kerentanan LFI adalah penyerang dapat menyiapkan file yang ketika diakses oleh penyerang dan sever mengeksekusi file tersebut, penyerang akan mendapatkan akses terhadap server atau bisa disebut <a href="https://www.getastra.com/blog/911/php-backdoor-web-shell-removal/"><i>web shells</i></a>.


#### Web Shells

Sederhanya, <i>Web Shell</i> merupakan kode yang dibuat oleh penyerang untuk dijadikan backdoor pada server. Dengan <i>Web Shell</i>, penyerang dapat secara aktif melakukan eksekusi command server melalui website, memberikan akses jarak jauh, melakukan pivoting, menjadikan server sebagai zombie, dan tidak menutup kemungkinan meningkatkan hak akses penyerang ke tingkat yang lebih tinggi (<a href="https://www.monitorteknologi.com/apa-itu-privilege-escalation/"><i>privilege escalation</i></a>).

Kegunaan Web Shell:

1. Persistent Remote Access
2. Privilege escalation
3. Pivoting and launching attacks
4. Turning server to a zombie
5. Command Execution

Contoh Web Shell:

1. <a href="https://github.com/PinoyWH1Z/C99Shell-PHP7">C99 Shell</a>
2. <a href="https://www.kali.org/tools/weevely/">Weevely</a>

### Bagaimana Cara Mengeksekusi Kode Apabila Penyerang Tidak Dapat Memasukkan File Ke Dalam Server?

Terdapat beberapa cara untuk melakukan eksploitasi LFI apabila penyerang tidak dapat memasukkan file ke dalam server, beberapa di antaranya adalah:

#### Kontaminasi Log File
1. Connect ke Webserver menggunakan netcat
2. Kirim Payload berikut
```php
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```
3. Execute the log file

#### Menggunakan PHP Wrappers
1. Format input parameter
```php
data:text/plain,<?php echo shell_exec(“${payload}”) ?>
```
2. Ganti <b>${payload}</b> dengan command yang diperlukan

### Remote File Inclusion

Mirip dengan Local File Inclusion, bedanya Remote File Inclusion berarti penyerang dapat membuat website mengeksekusi file yang telah disiapkan oleh penyerang pada server penyerang, sehingga penyerang tidak perlu memasukkan file berbahaya tersebut ke server target.


### Cara Mencegah Kerentanan File Inclusion

1. Mematikan fungsi yang berkaitan dengan eksekusi shell seperti eval, shell_exec, system, exec, passthru, dan proc_open.
2. Gunakan escapeshellarg() dan escapeshellcmd() untuk memastikan input yang dimasukkan user tidak dapat dieksekusi di shell.
3. Atur allow_url_include ke "off" apabila tidak dibutuhkan.
4. Lakukan sanitasi pada masukan user.

## Session Hijacking

### Deskripsi
Session hijacking adalah ketika seseorang jahat mencoba mencuri akses ke akun atau informasi online kita dengan cara meretas atau mencuri kode khusus yang digunakan untuk mengidentifikasi kita sebagai pengguna yang sah. Dengan kode ini, mereka bisa mengendalikan akun kita dan melakukan hal-hal yang tidak baik, seperti mencuri data pribadi.

### Metode

- [Physical Access](#physical-access)
- [Session Sidejacking](#session-sidejacking)
- [Session Fixation](#session-fixation)
- [Cross Site Scripting](#cross-site-scripting)
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

### Pencegahan Session Hijacking

- Penggunaan Secure dan HTTPOnly Flags pada Cookies
  
Memastikan bahwa cookie yang berisi informasi sesi hanya dikirimkan melalui koneksi HTTPS yang aman dan tidak dapat diakses oleh JavaScript dapat membantu melindungi sesi pengguna dari serangan XSS dan serangan man-in-the-middle.

- Penggunaan HTTPS

Menggunakan koneksi HTTPS yang aman adalah langkah kunci dalam melindungi sesi pengguna. Ini mengenkripsi data yang dikirimkan antara server dan peramban pengguna, mengurangi risiko peretasan sesi.

- Pola Nama dan Nilai Cookie yang Acak

Gunakan nama cookie yang sulit ditebak dan nilai yang unik untuk mengurangi risiko serangan session hijacking. Ini membuat lebih sulit bagi penyerang untuk menebak atau menebak cookie sesi pengguna.
