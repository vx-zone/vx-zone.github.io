---
layout: post
title: Rastgele Sayı Teorisi [TR]
date: 2022-09-03 15:42:31 +0300
description: Bilgisayar rastgele sayıyı nasıl üretiyor?
author: Utku Çorbacı
comments: true
tags: [Math, TR]
---

_“Mathematicians have tried in vain to this day to discover some order in the sequence of prime numbers, and we have reason to believe that it is a mystery into which the human mind will never penetrate.”_
-- **Leonhard Euler**

Bu yazı yazılırken [MathJax](https://www.mathjax.org/) kullanıldı. $$\TeX$$

# İçindekiler

<pre>
1. Rastgelelik Nedir?
2. Rastgele Üretme Yöntemleri?
3. Rastgele Sayı Üreticisinin İdeal Özellikleri
4. Mevcut Üreticileri İnceleyelim
</pre>

# Rastgelelik Nedir?
Ana konuya giriş yapmadan önce konu ile yakından ilintili bazı kavramlara göz atmalıyız. Bunlardan bir tanesi Rastgelelik. Rastgelelik, belirli bir dizilişin ve öngörülebilirliğin olmaması demektir. Örneğin tamamen rastgele olaylar sonucu meydana gelmiş birkaç elemandan oluşmuş bir dizi herhangi bir mantıksal kombinasyona veya dizilime kesinlikle uyum göstermez. Tabii hal böyleyken bir bilgisayarın ürettiği "rastgele" sayılara rastgele denilmez. Bunlara sözde rastgele ifadeler denir. Tabii siz tahmin edilebilir dediğimize göre bununla alakalı bir çalışma da yapılmıştır diye düşünürken ben linki bırakayım... [Buyurun](https://research.nccgroup.com/2021/10/15/cracking-random-number-generators-using-machine-learning-part-1-xorshift128/) 

# Rastgele Üretme Yöntemleri?
Öncelikle rastgele bir şeyler üretmek, bilim insanları için her zaman ilgi çekici olmuştur. Öngörülemeyen hesaplamalar sonucu çıkan hatalar içerisinden sayıları almak gibi bir işlem de tabii ki sözde rastgelelik sonucu olabilir. Fakat burada biraz fizikten ve sesten yardım almayı düşüneceğiz. Fizik derken şundan bahsediyordum : Kuantum Mekaniği üzerinde yapılan hesaplamaların çoğunda bir hata payı vardır. Bilim insanları bu konu için deney yaparlarken yine öngörülemeyen hatalar sonucu rastgelelik meydana geliyor işte bunu sözde rastgele adına kullanabiliyoruz. Atmosferik dünyadaki sesleri de bu iş için kullanabiliriz. Bilgisayar mikrofonundan (hz aralığı önemsiz şuan) aldığımız verileri sayısal verilere dönüştürüp işlersek rastgelelik ortaya çıkabilir.

Bu verilere göre rastgele üretme yöntemlerini ikiye ayırabiliriz. 
- Sözde Rastgele Sayı Üreticisi (Pseudo-Random Number Generator) -> Bir dizi matematiksel işlem kullanılması sonucu üretilir. Tahmin edilebilir.
- Gerçek Rastgele Sayı Üreticisi (True-Random Number Generator) -> Atmosferik sesleri işlemek gibi öngörülemeyen gerçek dünya girdileri ile çalışırlar.

Gerçek Rastgele Sayı Üreticileri'nin kullanım alanlarından örnek verecek olursak: Bilgisayarın her parçasının tahmin edilebilir şekilde tasarlanmasından yakınan Cloudflare yetkilileri, neredeyse web trafiğinin %10'unun üstünden aktığı Cloudflare'ın trafik şifrelemesini daha da güçlendirmek adına farklı bir yöntem bulmuşlar; Lav Lambaları! İşte [link!](https://www.youtube.com/watch?v=1cUUfMeOijg) video içerisinde Nick Sullivan'ın bahsettiği farklı metotları da duyacaksınız (kaotik sarkaç, radyoaktif kaynak...).

# Rastgele Sayı Üreticisinin İdeal Özellikleri
Rastgelikten, rastgele üretme yöntemlerinden bahsettik. Şimdi sözde rastgele sayı üreticilerinin ideal özelliklerinden bahsedeceğiz.

1. Tabii ki imkansız hale getiremeyeceğiz fakat tahmin edilemez olmalı.
2. Verilecek çıktıların hepsinin olasılığı eşit olmalı. Örneğin matematiksel hesaplama sonucu oluşturulan bir dizi içerisinde her elemandan aynı sayıda bulunmalı.
3. Matematiksel hesaplama sonucu oluşturulan dizi içerisindeki elemanlar arasında bir periyot olmamalı.

# Mevcut Üreticileri İnceleyelim

Mevcut üreticilerden önce olayı daha iyi anlamanızı sağlayacak çok küçük bir örnek göstereyim.

R() adında bir fonksiyonumuz var ve bu fonksiyonu her çağırdığımızda bize restgele bir sayısal değer döndürecek.
Bunun için özyinelemeli bir fonksiyonu kullanabiliriz.
Seed değerimiz $$a_0 = 2$$ olmak üzere genel terimi $$a_n = a_{n + 1} + 1$$ olan bir dizi üretirsek. Döndürdüğü son değere sürekli 1 ekleyecek. Fakat bu bahsettiğimiz ideal özelliklerin 1.sine aykırı. Dizi içerisindeki elemanlara bakarsanız çok rahat şekilde bir diziliş göreceğiniz için kuralı da kolaylıkla bulacaksınız. Bunu güçlendirmenin farklı bir yolu farklı işlemler eklemektir. Örneğin $$a_n = 2a_{n+1} + 1$$ Bunun sorunu ne diyeceksiniz. Pek tabii ilk madde için yine sıkıntı çıkartıyor. Fakat onun dışında bu tarz genel terimlerin sıkıntısı durmadan büyümesidir çünkü biz rastgele seçmek istediğimiz sayıların belli bir aralığa girmesini isteriz.

Bunun için de bir çözümümüz var. $$\bmod$$ operatörünü kullanmak :)\
Önceki örnek genel terimi birazcık düzenleyerek bu hale getirelim:\
$$a_n = (2a_{n+1} + 1) \bmod 100$$ ufak bir python scripti ile nasıl çıktı verdiğini görelim.\
```
$utku > python .\test.py
11
23
47
95
91
83
67
35
71
43
87
75
51
3
7
15
31
63
27
55
11
23
47
95
91
```
Sıkıntıyı fark ettiniz mi? 21. terimden sonra tekrar başa dönüyor. Bu da 3. maddeye aykırı geliyor. Pseudo üreticileri işte bu şekilde. Şimdi ünlü algoritmaları ve diller içerisindeki implementasyonlara göz atacağız.

## Blum Blum Shub
Blum Blum Shub, Lenore Blum, Manuel Blum ve Michael Shub tarafından 1986 yılında önerilen bir yalancı rastgele sayı üretme algoritmasıdır. İsminin nereden geldiğini anlamışsınızdır. Algoritma çok basit:\
1. Adım: Birbirine eşit olmama şartı ile belirleyeceğimiz iki asal sayının ismi sırayıla p ve q olsun.
2. Adım: Rastgele belirleyeceğimiz sayının ismi s olsun.
3. Adım: $$N = p \times q$$ işlemi ile N değişkenini hesaplayalım.
4. Adım: $$x_0 = s^2 \bmod N$$ olacak şekilde oluşturacağımız dizinin ilk terimini hesaplayalım.
5. Adım: $$x_n = x_{n - 1}^{2} \bmod N$$ denklemi ile birçok rastgele sayı üretelim.

Python İmplementasyonu\
[GitHub Gist](https://gist.github.com/polynomen/f803ecfe78b1387c9abd2fcb7b30f33d)
{% highlight python %}
p = 283
q = 79
s = 13
N = p * s
x = []

x.append((s ** 2) % N)
for i in range(1, 25):
    x.append((x[i - 1] ** 2) % N)

print(x)
{% endhighlight %}

## Mersenne Twister
Evet, geldik herkesin tanıdığı... Tanımıyor musunuz? Mersenne Twister implementasyonu birçok dilde rand fonksiyonu içerisinde çalışan algoritmadır. Bu dillerden bazıları: APL, IDL, R, Ruby, Free Pascal, PHP, Python, Lisp, Julia
Mersenne Twister algoritması 1997 yılında [Makoto Matsumoto](https://www.researchgate.net/profile/Makoto-Matsumoto-2) ve [Takuji Nishimura](https://www.researchgate.net/scientific-contributions/Takuji-Nishimura-8520730) beyefendiler tarafından geliştirilmiştir. İsmini, Mersenne asalını $$2^{19937} - 1$$ içerisinde bulundurmasından almıştır. Önceki genel terimimizin periyot uzunluğu 21'di. Mersenne Twister'ın özelliği de bunu mersenne asalı kadar büyütmesi.

### Algoritmik Detaylar
Buradan itibaren algoritmik detayların tamamı [resmi makaleden](http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/ARTICLES/mt.pdf) ve [wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister)'dan alıntı yapılarak yazılacaktır. (32 bit implementasyonu)

Bir Mersenne Twister uygulaması için başlatmadan önce tanımlamamız gereken birkaç sabit var.
```
(w,n,m,r) = (32,624,397,31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18
f = 1812433253

MT = [0 for i in range(n)]
index = n+1
lower_mask = 0x7FFFFFFF #(1 << r) - 1 // That is, the binary number of r 1's
upper_mask = 0x80000000 #lowest w bits of (not lower_mask)
```

Bu sabitlerin ne işe yaradığını wikipedia sayfası üzerindeki pseudocode'u yorumlarken açıklayacağız.

```
// Create a length n array to store the state of the generator
 int[0..n-1] MT
 int index := n+1
 const int lower_mask = (1 << r) - 1 // That is, the binary number of r 1's
 const int upper_mask = lowest w bits of (not lower_mask)
 
 // Initialize the generator from a seed
 function seed_mt(int seed) {
     index := n
     MT[0] := seed
     for i from 1 to (n - 1) { // loop over each element
         MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
     }
 }
```
Her biri w bitlik n adet değerden oluşan bir dizi tanımlamalıyız. Bu pseudocode'da da 0 ile başlayan ve n-1'e kadar uzanan bir dizi tanımlanmış. Bu dizi oluşturucunun anlık durumunu tutmak için tanımlanmış bir dizi. Pek tabii diğer algoritmalarda da karşılaştığımız gibi bunda da bir tohum belirlenmesi gerekiyor. Pseudocode üzerinde belirtilmiş tohum init fonksiyonunu python'a döktüğümüzde:

{% highlight python %}
def mt_seed(seed):
    # global index
    # index = n
    MT[0] = seed
    for i in range(1, n):
        temp = f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i
        MT[i] = temp & 0xffffffff
{% endhighlight %}

0xFFFFFFFF d değişkenine karşılık geliyor. Açıkça görülebilmesi için değeri direkt yazdım. Temperleme işlemi yapılıyor. Üstelik seed işleminin klasiği olarak MT dizisinin ilk elemanı gördüğümüz üzere belirlediğimiz, geri kalanı da ona göre hesaplanan elemanlardan oluşuyor.

```
 // Extract a tempered value based on MT[index]
 // calling twist() every n numbers
 function extract_number() {
     if index >= n {
         if index > n {
           error "Generator was never seeded"
           // Alternatively, seed with constant value; 5489 is used in reference C code[54]
         }
         twist()
     }
 
     int y := MT[index]
     y := y xor ((y >> u) and d)
     y := y xor ((y << s) and b)
     y := y xor ((y << t) and c)
     y := y xor (y >> l)
 
     index := index + 1
     return lowest w bits of (y)
 }

 // Generate the next n values from the series x_i 
 function twist() {
     for i from 0 to (n-1) {
         int x := (MT[i] and upper_mask)
                   + (MT[(i+1) mod n] and lower_mask)
         int xA := x >> 1
         if (x mod 2) != 0 { // lowest bit of x is 1
             xA := xA xor a
         }
         MT[i] := MT[(i + m) mod n] xor xA
     }
     index := 0
 }
```

extract_number() fonksiyonumuz, MT dizisi içerisindeki temperlenmiş değeri dışa çıkartıyor. Seed değeri belirlendikten hemen sonra MT dizisi içerisindeki değerlerin temperlenme ve yeniden hesaplanması aşağıdaki formül ile yeniden yapılıyor. $$x_{i}=f\times (x_{i-1}\oplus (x_{i-1}\gg (w-2)))+i $$

twist() fonksiyonu x_i genel terimine göre diğer elemanları yeniden hesaplamak üzere çağırılan bir fonksiyon

xA matematiksel gösterim:


$${\displaystyle {\boldsymbol {x}}A={\begin{cases}{\boldsymbol {x}}\gg 1&x_{0}=0\\({\boldsymbol {x}}\gg 1)\oplus {\boldsymbol {a}}&x_{0}=1\end{cases}}}$$


{% highlight python %}
# Extract a tempered value based on MT[index]
# calling twist() every n numbers
def extract_number():
    global index
    if index >= n:
        twist()
        index = 0

    y = MT[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index += 1
    return y & 0xffffffff


# Generate the next n values from the series x_i
def twist():
    for i in range(0, n):
        x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0:
            xA = xA ^ a
        MT[i] = MT[(i + m) % n] ^ xA
{% endhighlight %}

Tüm Script

{% highlight python %}
# coefficients for MT19937
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18
f = 1812433253


# make a arry to store the state of the generator
MT = [0 for i in range(n)]
index = n+1
lower_mask = 0x7FFFFFFF #(1 << r) - 1 // That is, the binary number of r 1's
upper_mask = 0x80000000 #lowest w bits of (not lower_mask)


# initialize the generator from a seed
def mt_seed(seed):
    # global index
    # index = n
    MT[0] = seed
    for i in range(1, n):
        temp = f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i
        MT[i] = temp & 0xffffffff


# Extract a tempered value based on MT[index]
# calling twist() every n numbers
def extract_number():
    global index
    if index >= n:
        twist()
        index = 0

    y = MT[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index += 1
    return y & 0xffffffff


# Generate the next n values from the series x_i
def twist():
    for i in range(0, n):
        x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0:
            xA = xA ^ a
        MT[i] = MT[(i + m) % n] ^ xA


if __name__ == '__main__':
    for i in range(0, 25):
        mt_seed(i)
        print(extract_number())
{% endhighlight %}
