# Modul 2 Part 1 Web App Security

## Cross Site Request Forgery 

### Deskripsi
Cross Site Request Forgery merupakan suatu serangan yang memaksa end user untuk melakukan tindakan yang tidak mereka sadari pada web di mana mereka saat ini sudah terautentikasi (bisa berupa login dengan akun user dan kata sandi atau metode autentikasi lainnya)

Cara kerja serangan:
1. Untuk GET Scenario:
    - Craft a fake URL 
    Menyusun sebuah URL (Uniform Resource Locator) dengan tujuan tertentu untuk membuat korban mengklik link URL tersebut. URL yang dibuat merupakan URL palsu dengan tujuan memanipulasi korban yang dapat menguntungkan pelaku. 
    - Craft a fake image
    Penyerang dapat mengirimkan fake image ke user yang telah terautentikasi dan image tersebut mengandung kode atau tindakan yang dapat membahayakan user tersebut. Akibatnya, ketika pengguna membuka gambar tersebut, penyerang akan menjalankan tindakan berbahaya tanpa sepengetahuan user. 

2. Untuk POST Scenario:
    - Create a fake (hidden form):
    





