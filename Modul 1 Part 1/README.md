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
Description of File Inclusion Vulnerabilities goes here.

## Session Hijacking
Description of Session Hijacking goes here.

## Cross-Site Scripting (XSS)
Description of Cross-Site Scripting (XSS) goes here.