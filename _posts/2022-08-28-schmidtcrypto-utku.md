---
layout: post
title: Schmidt-Samoa Şifrelemesi [TR]
date: 2022-08-24 16:45:29 +0300
description:  
author: Utku Çorbacı
tags: [Math, Crypto, TR]
---

<pre>
1. Schmidt-Samoa Şifrelemesi Genel Bilgi
2. Senaryo
3. Şifreleme ve Çözme İşleminin Matematiksel Teorisi
4. Uygulama
5. Python İmplementasyonu
</pre>

“I learned very early the difference between knowing the name of something and knowing something.”
― **Richard P. Feynman**

# Schmidt-Samoa Şifrelemesi Genel Bilgi
Katja Schmidt-Samoa tarafından 2005 yılında oluşturulan asimetrik bir şifreleme kendisi. Rabin şifreleme metoduna rakip olarak oluşturulduğunu düşünüyorum. Özellikle wikipedia'da sürekli Rabin metodu ile arasındaki belirgin farklar vurgulandığı için... Hakkındaki detaylı bilgiyi matematiksel teori kısmında vereceğim.

# Senaryo
Kriptoloji hakkında yazıların çoğunda görmüşsünüzdür Alice Bob'a bir şeyler yollar ve işlem şifrelenir... Yani olaylar hep bir senaryo üzerinden yürür. İşin raconu budur. Dolayısıyla biz de bugün tamamen özgün, yenilikçi ve fantastik bir senaryo uyduracağız.

Ağustos Böceği ile Karınca.

Ağustos böceği ile karınca tarlada otururlarken karınca tam "global" derken ağustos böceği sözünü kesmiş ve şifreli konuşalım demiş ve kullanacakları şifrelemenin(Schmidt Samoa) detaylarını başlamış anlatmaya...

# Şifreleme ve Çözme İşleminin Matematiksel Teorisi
## Şifreleme Matematiksel Teori
Rastgele( :D ) seçilecek ve yeterince büyük(neden yeterince dediğimi de söyleyeceğim) p ve q adında iki adet asal sayımız olsun. Bu iki sayıyı açık ve kapalı anahtarları hesaplarken kullanacağız.
> Açık Anahtar(Public Key) = N\
> Kapalı Anahtar(Private Key) = d\
> $$\text{lcm()} = \text{ekok()}$$
$$N = p^2 \times q$$
$$d = N^{-1} \bmod {\text{lcm}}(p - 1, q - 1)$$

> **Eğer birbirine yakın iki asal sayı seçerseniz; p ve q sayıları, açık anahtarın küp kökü civarında olacağı için hızlıca tahmin edilebilir.**

Oluşturulacak şifreli metin c ve plaintext(elimizde bulunan şifresiz metin) metin m olmak üzere; 
$$c=m^{N} \bmod N$$ 

## Çözme Matematiksel Teori

$$m=c^{d} \bmod p \times q$$ 

Uygulama bölümünde hepsini uygulayacağız.

# Uygulama

Uygulamayı aslında implemente edeceğimiz python scripti üzerinden yürüteceğiz.

1. Adım: p, q değerlerinin belirlenerek N'nin (Public Key) hesaplanması.
2. Adım: d'nin (Private Key) hesaplanması.
3. Adım: Yazının şifrelenmesi.**

# Python İmplementasyonu
Saygıdeğer Kağan Işıldak'ın yayınladığı [GitHub repo'sunda](https://github.com/kaganisildak/python-schmidt-samoa) python2 olması haricinde güzel implemente edildiğini görüyoruz.

`git clone https://github.com/kaganisildak/python-schmidt-samoa.git` komutu ile indirdikten sonra klasörün içine geçerek `py -2.7` komutu ile python2'yi çalıştıralım ve şu şekilde devam edelim:

``` 
$utku> py -2.7
Python 2.7.18 (v2.7.18:8d21aa21f2, Apr 20 2020, 13:25:05) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import schmidtSamoa as SS
>>> dir(SS)
['__all__', '__builtins__', '__doc__', '__file__', '__name__', '__package__', '__path__', 'core', 'decrypt', 'encrypt', 'generateKey', 'key', 'prime']
>>>
```
İçerisinde bulunan yapılara göz attığımızda ilk başta inceleyeceğimiz noktayı rahatlıkla görebiliyoruz. Öncelikle anahtarları üreten fonksiyona gidelim.

{% highlight python %}
def generateKey(n):
	p, q = getPrime(n), getPrime(n)

	n = p * q

	pk = pow(p, 2) * q 
    # Public Key
	sk = inverse(pk, lcm(p - 1, q - 1))
    # utku's description :
    # sk = pow(pk, -1, lcm(p - 1, q - 1))
    # Secret Key

	return(pk, (sk, n))
{% endhighlight %}
`getPrime(n)` fonksiyonu Miller-Rabin Asallık Testi'ni kullanarak belirtilen argüman ile birlikte asal sayı üretmek ile görevli.
```
>>> import schmidtSamoa as SS
>>> pubkey, privkey = SS.generateKey(16)
>>> pubkey
49160314876397L
>>> privkey
(379751297L, 1569263411L)
```

Şifreleyeceğim mesajı message değişkeninde saklayacağım ve `encrypt(message, pubkey)` fonksiyonu ile şifreleyeceğim.

```
>>> message = "global"
>>> encrypted = SS.encrypt(message, pubkey)
>>> encrypted
'MzM0MjUxMjM1MDY2NjQgNDg5NTI0MzE5NjY1OTEgOTI4ODAxNTY2ODIwOSA0MjgwNzIxMjM1OTc5MCA0NTQ3Njc3MjczNzA4OCA0ODk1MjQzMTk2NjU5MQ=='
```

{% highlight python %}
def encrypt(message, pk):

    """
    cipher = []
    for char in message.encode():
        newval = str(pow(ord(char), pk, pk)) + " "
        cipher.append(newval)
    return base64.b64decode(''.join(cipher).strip().encode())"""

    return base64.b64encode(''.join([str(int(pow(ord(char), pk, pk))) + " " for char in message]).strip().encode())
{% endhighlight %}

Şifreleme teorisini hatırlayalım:

$$c=m^{N} \bmod N$$

Python karşılığı da `pow(m, N, N)`

Buradaki m değişkeninin anlamı şifreleyeceğimiz yazının içerisindeki belirtilen indexde bulunan karakterin decimal karşılığı. Yaptığı şu şekilde:

1. Adım: Sıradaki karakteri seç
2. Adım: Karakterin sayısal karşılığını al
3. Adım: Şifreleme işlemine sok
4. Adım: Başa dön
5. Adım: İşlem bitince base64 ile şifrele

Decrypt işleminin nasıl işlediğini tahmin etmek zor değil. Kod dökümü:

{% highlight python %}
def decrypt(cipher, sk, n):

    """
    plain = []
    for num in base64.b64decode(cipher).split(" "):
        newval = str(chr(pow(num, sk, n)))
        plain.append(newval)
    return ''.join(plain)"""

    return ''.join([str(chr(pow(int(num), sk, n))) for num in base64.b64decode(cipher).split(" ")])
{% endhighlight %}

Decrypt işleminin matematiğini hatırlayalım:
$$m=c^{d} \bmod p \times q$$ 


1. Adım: Base64 decode
2. Adım: Boşlukları ayır
3. Adım: Ayrılan yeri matematiksel işleme sok
4. Adım: Birleştir

```
>>> decrypted = SS.decrypt(encrypted, privkey[0], privkey[1])
>>> decrypted
'global'
```