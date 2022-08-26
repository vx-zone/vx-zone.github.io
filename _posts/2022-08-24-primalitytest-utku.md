---
layout: post
title: Miller-Rabin Primality Test [TR]
date: 2022-08-24 16:45:29 +0300
description: Havalı asal sayı algoritmasına bir bakış atalım
author: Utku Corbaci
tags: [Math, TR]
---

_“Perspective is not a science but a hope”_
-- **John Berger**

# İçindekiler

<pre>
1 Olayın Tarihçesi
2 Matematiksel Teori
    2.1 Fermat Çarpanlara Ayırma
    2.2 Fermat Asallık Test
    2.3 Miller-Rabin Asallık Testi
    2.4 Örnek Bir Soru
3 Python İmplementasyonu
</pre>

# Olayın Tarihçesi
> Olaya değinmeden önce asal sayılara değineceğim. Birden büyük, sadece kendisine ve bire bölünen tam sayılara asal sayı denir. En küçük asal sayı 2'dir.

Matematik üzerinde hemen hemen her şey birbirine bağlı olarak, "ihtiyaç üzerine" geliştirilmiştir -veya keşfedilmiştir [(?)](https://evrimagaci.org/matematik-bir-kesif-mi-yoksa-icat-mi-8094)-. İnsanlar asal sayı testi adı altında muhtelif algoritma fikirleri ortaya çıkarıyordu. Örneğin ilk test M.Ö 240 yılında Erastotenes tarafından önerildi ve ismi de Erastotenes Kalburu oldu. Erastotenes kalburuna göre eğer sayının kareköküne kadar tüm asal çarpanlar denenmiş ve hala bir çarpan bulunmadıysa kendisinden ve başka çarpanı yoktur demek oluyordu. Bu ve benzeri sistemler karşılaşılan büyük sorun nedeniyle demode olmuştu. BÜYÜK SAYILAR... Bu konuda yapılması gerekli ilk şeyin daha optimize durumda çalışan bir çarpanlara ayırma algoritmasıydı. İşe koyulan Fermat 17. YY'da Fermat Teoremi adı altında bir teorem yayınladı (matematiksel teori kısmında açıklanacak).  1976 yılında Miller daha sonrada Rabin Genişletilmiş Riemann hipotezine dayanan olasılık algoritmaları geliştirdiler detayına matematiksel teori kısmında değineceğiz.  

> Kısa bir dipnot : 1976 yılında Miller testi keşfediyor. 1980 yılında Micheal O. Rabin testi koşulsuz olacak şekilde geliştiriyor.

# Matematiksel Teori
Bu yazı yazılırken [MathJax](https://www.mathjax.org/) kullanıldı. $$\TeX$$

Öncelikle burada değineceğiz dediğim Fermat Teoremi'nden bahsetmekte fayda var. 
## Fermat Çarpanlara Ayırma
Bu metot, tek bir tam sayının iki kare farkı şeklinde yazılmasına dayanır.

Gösterim:
N bir tek pozitif tam sayı olmak üzere:
$$N = a^2 - b^2$$

Bu durumda N sayısını oluşturan çarpanlar $$(a - b)(a + b)$$ olacaktır.

$$a = \frac{c + d}{2}$$ ve $$b = \frac{c - d}{2}$$ olmak üzere
$$N = (\frac{c + d}{2})^2 - (\frac{c - d}{2})^2$$

Şeklinde gösterildiğinde N tek olduğundan toplama çıkartma kuralları gereği (çift - tek = tek, tek - tek = çift, çift - çift = çift (-TYT çalışanlar not alabilir-)) c ve d tek olacaktır (ifadede gösterilen _yarım_ terimler tam sayıdır).

## Fermat Asallık Test 
Kısaca bundan da bahsetmeden olmaz. Matematiksel gösterim şu şekilde : 
$$\alpha^{p-1} (mod p) $$ 
Konsept de şu:
Örneğin biz yukarıdaki matematiksel gösterimde p sayısının asal olup olmadığını test etmek istiyoruz. Bunun için p ile bölünemeyen rastgele bir $$\alpha$$ sayısınaihtiyacımız var.
$$\alpha = 7$$ ve $$p = 5$$ diyecek olursak:
$$7^{4} mod 5 $$ ilgili işlemi yaptığımız zaman sonuç 1 olarak geldiğinden; p sayısı asaldır.

## Miler-Rabin Asallık Testi
Çoğu kaynakta Miller-Rabin Asallık Test'inin Fermat'ın asallık testine benzer şekilde çalıştığından bahsedilmiş. Şimdi Miller-Rabin Asallık Testi'nin algoritma tanımını yapalım sonra onun üzerinden yorumlayalım.

1. Adım : $$n > 2$$ olmak üzere test edeceğimiz asal sayı n olsun.
2. Adım : $$n - 1 = 2^k \times m$$ şeklinde yazalım. k ve m sayılarını bulalım.
3. Adım : $$b_i = 2^m (mod n)$$ Sonuç $$\mp 1$$ çıkana kadar devam edelim.
$$b_{i+1} = b_i^{2} (mod n)$$

## Örnek Bir Soru
Soru: 283 sayısı asal mıdır?

Soruyu çözmeye zaten 2. adımdan başlayacağız çünkü sayı direkt verilmiş.
$$\frac{282}{2} = 141$$ olduğundan ve 141'in tekrar ikiye bölümünden tam sayı değeri alamayacağımızdan dolayı $$282 = 2^1 \times 141$$
Yani $$k = 1, m = 141$$ olacaktır. 

$$\gg b_0 = 2^{141} mod 283$$\
$$\gg b_0 = 282$$\
$$\gg b_1 = 282^2 mod 283$$\
$$\gg b_1 = 1$$\

Eğer sonuç -1 çıkıyorsa sayı asal değildir.
Eğer sonuç +1 çıkıyorsa sayı asal sayıdır. Buna göre 283 sayısı asaldır.

# Python İmplementasyonu
Şimdi yukarıda verdiğimiz algoritmayı python'a dökelim.

[GitHub Gist](https://gist.github.com/polynomen/4b8975c04127225a3a198b0a2490ff40)
{% highlight python %}
def main():
    number = int(input("Insert an odd number: "))
    #step 1 - select a number in this range (n > 2)
    if(number <= 2 and 
    number % 2 == 0):
        print("Please insert an odd number in this range (n > 2) ")
        return
    
#step 2 -- n - 1 = 2^k \times m

    k = 0
    m = 0
    if ((number - 1) % 2 == 0):
        k = (number - 1) // 2
        while (k % 2 == 0):
            k = k // 2
        m = (number - 1) // k
        print("k = {0}, m = {1}".format(k, m))
    else:
        print("error")
        return
    
#step 3 -- $b_i = 2^m (mod n) \mp 1
# \mp = minusplus
# ** = ^

    b = (2 ** k) % number
    while True:
        if(b == 1):
            print("{0} is prime".format(number))
            return
        if(b == -1):
            print("{0} is not prime".format(number))
            return
        b = b ** 2 % number

if __name__ == '__main__':
    main()
{% endhighlight %}

