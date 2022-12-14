---
layout: post
title: Random Number Theory [EN]
date: 2022-09-03 15:42:31 +0300
description: Take a look how computers generate random numbers
author: Ahmet Göker
comments: true
tags: [Math, EN, Algorithm, Calculus, Code]
---

_“It is impossible for any number which is a power greater than the second to be written as a sum of two like powers.”_
-- **Pierre De Fermat**



# content

<pre>
0x01. Number Theory
0x02. Random Numbers by using computer algorithms
0x03. Techniques Of Generating Random Number
</pre>



# Number Theory

When we talk about this theory, we should consider this as pure mathematics because it's devoted primarily to the study of the integers and integer-valued functions. Everything has been started by famous german mathematician 
**Carl Friedrich Gauss** mentioned,  "Mathematics is the queen of the sciences—and number theory is the queen of mathematics." When we study this branch, there will be a lot of unasked questions in your mind.
Everyone who is interested in this pure mathematics, All of you have been interested in the prime numbers those are special because none of them can be factored into smaller numbers. But does this 
sequence follow a pattern? For example ... 

**Euclid said**, "Well, actually, in Book IX, Proposition 20 of my Elements, I showed that there are infinitely many primes." but what said Hardy?, "Yes, Euclid, my good sir. Your proof is well known to everyone in the room, except possibly the honorable Pythagoras, who is several centuries your senior. But is 
there a pattern to the infinite sequence of primes? Herr Gauss, perhaps you would like to start off our discussion? " hmm interesing right. Lets take a look what other mathematicians said about this conclusion."


**Carl Friedrich Gauss**, what we mentioned earlier he said: "Well, as you examine larger and larger integers you find that there are fewer and fewer primes. On average, the primes become more spread out the farther you go. Of the numbers less than one hundred, 25% are prime, but of the numbers less than one million, only about 8% are prime. I even found formula that approximates how many primes there are less than 
any given number. It's quite remarkable-it has to do with calculus and logarithms 
and such."

I want to remind you quickly about integers,primes, and rational numbers the functionality of them.


We have positive integers and negative integers. Let me explain what integers are..

**Integers** --> it means that the number zero (0), a positive natural number (1, 2, 3, etc.) or a negative integer with a minus sign (−1, −2, −3, etc.).

**prime numbers** --> The positive integers that have only 1 and themselves as positive divisors such as; 2,3,5,7,11,13... and so on

**rational numbers** --> the set of rational numbers can be constructed using the equivalence classes of pairs of integers where the second integer in the pair is not zero,
where $$(a, b) ≈ (c, d)$$ if and only if $$a ⋅ d = b ⋅ c$$; addition and multiplication of rational numbers. As we can read through this quotes by famous mathematicians, that numbers theory is like an apple being thrown in the space but we do not know exactly where it will be to land.

Now we are going to discuss and applicate such numbers in our modern computer algorithms to understand and secure them as much as possible we can.



# Random Numbers by using computer algorithms

We will discuss later the techniques of selecting random numbers generation system.Firstly, Let me explain why should we use random number generation to secure our being encrypted messages.
I want to ask you something. Have you ever heard about **Applications of Congruence** I think yes right? because we will use this technique a lot when we want to select our random numbers to drop into our algorithms

I want to explain this more understandabely because there are some confusing however, ı ought to illustrate what **Conqruence** is, and what does have to do with **pseudorandom** algorithm


**Conqruence** : Congruences have many applications to discrete mathematics, computer science, and many other disciplines. We will introduce one applications in this section:  the generation of pseudorandom numbers.

If you are ready lets get started.

## Pseudorandom Numbers

Randomly chosen numbers are needed to be generated through computer simulations. Those numbers are being generated by systematic computer methods , and are not truly random because we call them **pseudorandom**
The most commonly used will be produced by **linear conqruence** for generating pseudorandom numbers is the linear conqruential method. We will discuss this method more in depth.

In order to understand this, i am going to demonstrate four integers; the **modules** m, **multiplier** a, **increment** c, and **seed** $$X0$$, with 

$$2\leq a < m$$,
$$0\leq c <m$$, 
$$0\leq X0 <m$$

We use this sequence of pseudorandom numbers will be defined as Xn $$0\leq X0 < m$$ for all n, by successively using the recursively defined 

$$Xn+1 = (A.Xn+C) mod m$$


We are going to generate a pseudorandom numbers generated by the linear conqruence method with 
modules m=9, 
multiplier a =7,
increment  c =4, 
and seed  Xn =3


We shall be able to compute and use these integers successfully:

 $$X_n+1 = (7X_n + 4) mod 9$$ 

beginning by inserting the seed x0 = 3 to find x1. We find that
$$X_1 = 7x0 + 4 mod 9 = 7 ⋅ 3 + 4 mod 9 = 25 mod 9 = 7$$,
$$X_2 = 7x1 + 4 mod 9 = 7 ⋅ 7 + 4 mod 9 = 53 mod 9 = 8$$,
$$X_3 = 7x2 + 4 mod 9 = 7 ⋅ 8 + 4 mod 9 = 60 mod 9 = 6$$,
$$X_4 = 7x3 + 4 mod 9 = 7 ⋅ 6 + 4 mod 9 = 46 mod 9 = 1$$,
$$X_5 = 7x4 + 4 mod 9 = 7 ⋅ 1 + 4 mod 9 = 11 mod 9 = 2$$,
$$X_6 = 7x5 + 4 mod 9 = 7 ⋅ 2 + 4 mod 9 = 18 mod 9 = 0$$,
$$X_7 = 7x6 + 4 mod 9 = 7 ⋅ 0 + 4 mod 9 = 4  mod 9 =  4$$,
$$X_8 = 7x7 + 4 mod 9 = 7 ⋅ 4 + 4 mod 9 = 32 mod 9 = 5$$,
$$X_9 = 7x8 + 4 mod 9 = 7 ⋅ 5 + 4 mod 9 = 39 mod 9 = 3$$
 
 
We are seeing that X0 = X9 thus it means that after 9th is going to be the same because we just used normal pseudorandom generator.


3, 7, 8, 6, 1, 2, 0, 4, 5, 3, 7, 8, 6, 1, 2, 0, 4, 5, 3,....  as you can see after 9.th will be same.


Now that we have basic understanding of pseudorandom..

{% highlight python %}


#### generate random integer values
from random import seed
from random import randint
#### seed random number generator
seed(2)
#### generate some integers
for _ in range(100):
	integer = randint(0, 100)
	print(integer)

{% endhighlight %}

> Output:
7
11
10
46
21
94
85
39
32
77
27
77
4
74
87
20
55
81
50
92
65
47
69
56
64
34
4
3
46
59
40
48
54
67
21
71
22
30
29
3
22
41
22
17
65
65
46
65
86
71
23
57
53
94
67
97
46
75
45
46
57
20
96
51
91
94
59
83
67
31
62
35
63
64
65
45
84
58
59
44
72
92
71
92
58
62
84
28
41
89
21
78
34
98
61
39
38
90
64
71

We just used basic pseudorandoöm generator script with python. As you can see that, **linear conqruence** can be used by any programming language but other techniques shall be used .



# Techniques Of Generating Random Numbers


Oke, are you ready to hear the weirdest and the most Wacky Random Number Generator Techniques. There are actually a lot, but i will give an example by one of them;

**Your own Movememt** Yes sounds weird right? hihi actually not because lets cover this topic more in depth.

Linux operating system powers, computers, servers, and more.. these need to be generated, being used by trustworthy random number generator available for various purposes.
We might not know that Linux Kernel has pool of random numbers. When random numbers are requested,it refills the number pool by tracking mouse movements, and inputs/outputs.
Once time, when you might want to use random numbers from Linux Kernel, you can actually be seed. I will give you the link where you can try it out --> [Linux Movement Mouse](http://www.russellcottrell.com/mousePointerRNG.htm)



### Lagged Fibonacci generator

> Important (I will use a bit from wikipedia source)

We discussed earlier about **linear conqruence** algorithm. This algorithm is This class of random number generator actually the predecessor of **linear conqruencer** but with more improvements and being improved with fibonnaci sequence

The Fibonacci sequence may be described by the recurrence relation (I am not going to explain what **recurrence relation** is but i will drop the link ---> [recurrence relation](https://en.wikipedia.org/wiki/Recurrence_relation))

The expression will be as follows:

$$S_n = S_{n-1} + S_{n-2}$$ 

Hence, the new term is the sum of the last two terms in the sequence. This can be generalised to the sequence:

$$S_n \equiv S_{n-j} \star S_{n-k} \pmod{m}, 0 < j < k$$


### Properties of lagged Fibonacci generators

Lagged Fibonacci generators have a maximum period of $$(2k − 1)×2M-1$$ if addition or subtraction is used, and $$(2k − 1) × k$$ if exclusive-or operations are used to combine the previous values. If, on the other hand, multiplication is used, the maximum period is (2k − 1) × 2M−3, or 1/4 of period of the additive case.

For the generator to achieve this maximum period, the polynomial:

$$y = xk + xj + 1$$

must be primitive over the integers mod 2. Values of j and k satisfying this constraint have been published in the literature. 

> Popular pairs of primitive polynomial degrees:  j 7 5 24 65 128 6 31 97 353 168 334 273 418
k 10 17 55 71 159 31 63 127 521 521 607 607 1279 



You might be wondering how we can use this pseudorandom generator right?

Have a meet with **Subtract with carry**

this generator is being by c++ or cpp


let me explain a bit about **substratc with carry **

--> **Subtract-with-carry** is a pseudorandom number generator: one of many algorithms designed to produce a long series of random-looking numbers based on a small amount of starting data. It is of the lagged Fibonacci type introduced by George Marsaglia and Arif Zaman in 1991. "Lagged Fibonacci" refers to the fact that each random number is a function of two of the preceding numbers at some specified, fixed offsets, or "lags". 

The algorithm part of this **carry** is:

Sequence generated by the subtract-with-carry engine may be described by the recurrence relation:

$$x(i) = (x(i-S) - x(i-R)-cy(i-R)) mod m$$

Constants S and R are known as the short and long lags, respectively Therefore, expressions  $$x(i-S)$$ and x(i − R)  correspond to the S-th and R-th previous terms of the sequence. S and R satisfy the condition 0 < S < R 


I will put the link of C++ library where you can use this generator through this library --> [check](https://en.wikipedia.org/wiki/C%2B%2B11)



# Summary

I was trying to explain these algorithms as best as i could of course there can be some mistakes that I could not see. I will share the link where you can find more such algorithms.

[Rejection Samples](https://en.wikipedia.org/wiki/Rejection_sampling#Algorithm),
[Freecy](https://en.wikipedia.org/wiki/Freeciv),
[Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister),
[VIC Cipher](https://en.wikipedia.org/wiki/VIC_cipher),

I would also recommend you some books where you can learn and practise it. So as to become a superior malware analyst, you do not have to be very good at maths, you should think matematically.

video 1 --> [random number generator](https://www.youtube.com/watch?v=_tN2ev3hO14)
video 2 --> [Blum-Blum-Shub](https://www.youtube.com/watch?v=M2VOfZJyk_o)
video 3 --> [Game Engine Theory](https://www.youtube.com/watch?v=bd7k037zykY)





If you were unable to understand this mindset, please ask us for help... Thank you for spending your valuable time for this content. I will see you in the next time. More awesome blogs will be written!!

Ahmet Göker




