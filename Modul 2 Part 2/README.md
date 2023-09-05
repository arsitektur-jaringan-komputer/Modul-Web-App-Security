# Modul 2 Part 2 Web App Security

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
