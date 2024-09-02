# Hawtsauce SQL Injection Vulnerability Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.x-green.svg)

Hawtsauce SQL Injection Vulnerability Scanner, belirli bir URL veya URL listesi üzerinde SQL Injection zafiyetlerini tespit etmek için kullanılan bir Python aracıdır. Bu araç, farklı veritabanı türlerine göre özelleştirilebilir SQL payload'ları kullanır ve zafiyet tespit edildiğinde kullanıcıya durup durmayacağını sorar.

## Özellikler

- **Farklı Veritabanı Türleri**: MySQL, MSSQL, PostgreSQL ve Oracle veritabanlarını destekler.
- **GET ve POST Desteği**: URL parametrelerinde SQL Injection zafiyetlerini hem GET hem de POST metodlarıyla test edebilir.
- **Dinamik Payload Üretimi**: Dinamik olarak SQL payload'ları oluşturabilir ve çeşitli varyasyonlarla test yapabilir.
- **Çoklu Thread Desteği**: Birden fazla URL'yi aynı anda taramak için çoklu thread desteği.
- **Kullanıcı Onayı**: SQL Injection zafiyeti tespit edildiğinde kullanıcıdan taramaya devam edip etmeyeceği sorulur.
- **Loglama**: Tüm test sonuçları ve hatalar loglanır.

## Kurulum

### Gereksinimler

- Python 3.x
- Gerekli Python kütüphanelerini kurmak için:

```bash
pip install -r requirements.txt


