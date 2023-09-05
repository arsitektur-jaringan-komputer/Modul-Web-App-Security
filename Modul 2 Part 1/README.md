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
  




