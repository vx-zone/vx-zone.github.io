---
layout: post 
title: Miller-Rabin Primality Test [EN]
date: 2022-08-28 16:45:29 +0300
description: Have you ever used this algorithm?
author: Ahmet Göker
tags: [Math, EN, Algorithm, Calculus]
---


-"
“Sometimes it is the people no one can imagine anything of who do the things no one can imagine.”
**Alan Turing**

# Topics


0x01 Prime Numbers
0x02 Fermat's Primality test 
0x03 Primality Rabin Test
  3.1 A proof of error bound
0x04 Rabin Encryption



# Intro

Hello Amazing hackers, welcome back to my first blog in this community. I am thrilled to demonstrate these topics with you. Most people are thinking that malware has not to do with mathematics, but I think that it should be recommended to learn at least basic algebra and modulo arithmetic. Today, i want to illustrate about Primality Rabin Test as well as the encrypton method. Let me briefly introduce how this asymmetric encryption method works. This method works as follow:

First of all, we need to get an input value from the user, we will want to determine and test whether input is prime or not. This method is used for cryptography and will be used for encryption. These are the types of Primality Test algorithm:

0x01 --> Determininstic Algorithm

0x02 --> Divisibility Algorithm

0x03 --> Probabilistic Algorithm

0x04 --> Fermat Primality Test

I shall demonstrate 0x04 and 0x03 more in depth later on. I hope you will enjoy this blog. I will try to make this blog understandable.




# Prime Numbers

> In order to understand Rabin Encryption algorithm, we ought to understand what prime numbers are...

As you already might know from calculus class, that prime numbers should be defined greater than 1, and its only divisible by itself. We can consider number "5" this is a natural prime number because the only ways of writing it as a product, 1 × 5 or 5 × 1, involve 5 itself. However, 4 is a composite number because it is divisible by [1,2,4].

Belongings of being prime is called "Primality" we frequently hear this term from calculus class. Primality, is being used a lot, the reason of that, it is a simple method but works leisurely. Take a look to this definition -->  **GCD(a,b) = 1**

Integers a and b not both zero are relatively prime (sometimes called coprime)

In order to understand this definition, we can take 2 relatively prime numbers (5,13) because **GCD(5,13) = 1** to inform yourself well, take a look --> [relatively prime](https://www.mathsisfun.com/definitions/relatively-prime.html) 

> I will discuss later on, in my random number theory blog about Euclid's lemma

  Usually lemma means an intermediate result, or a result used to deduce an important theorem or proposition, but in this case Euclid's lemma is a critical resulting its own right.
  
before going to **Fermat's Primality test** I am willing to prove this. 


     
      
We can consider, if a | (bc) with gcd(a,b) = 1 then a | c

Let us now prove the lemma


**proof:**

By bezout's identity not given earlier, but you can check it out [bezout's theorem](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_theorem)

    if gcd(a,b) = g then there are integers m and n such that ma+nb = g
    
there are integers m and n such that

    ma+nb = 1, this reason is that [because we are given gcd(a,b) = g = 1]
    
Now we are given that a | (bc), therefore there is an integer k such that

    a.k = b.c
    
subsitiuning this into (*) gives
  
    m(a.c) + n(b.c) = m(a.c) + n(a.k) = a[mc+nk] = c    (*)
    
This result a[mc+nk] = m(a.c) + n(a.k) = c implies that a X (integer) = c, so we have a | c.

This completes our proof.


# Fermat's Primality test

is a probabilistic test, as we might quess from this term. To determining whether a number is a probable prime, we can get help from [Pepin's test](https://en.wikipedia.org/wiki/P%C3%A9pin%27s_test). I want to explain this term easily to make it more sense and understandable to people.

Alex needs to choose two very large primes p and q. It's not enough for him to choose two very large, but possibly composite, numbers p and q. In the first place, if p and q are not prime, Alex will need to know how to factor them in order to decrypt Alice's message. But even worse, if p and q have small prime factors, then Eve may be able to factor pq and break Alex's system

His job is thus being faced with the task of finding large prime numbers. More precisely, he needs a way of determining between two prime numbers and composite numbers.


Let's suppose, that Alex has chosen the rather large number

 > n = 31987937737479355332620068643713101490952335301
  
So, he wants to know whether n is a prime number or not. First Alex searches for small factors, but he finds that n is not divisible by any primes smaller than 1000000


Thus, his job is that computing the quantity:
    
 > $$2^n-1 = 128126595355135906413360121624715836053160074 (mod n)$$
      
 Awesome, we see that n is a composite number. Though it does give us any indication how to factor n why? how? lets refresh our Fermat's theory
 
 ## Fermat's little Theorem
 
 Let p be a prime number. Then 
 
  
 $$a^p \equiv a (mod p)$$ for every integer a. If p is not divisible by a, then the first version of Fermat's little theorem implies that $$a^{p-1} \equiv 2 (mod n)$$ 
 
 by proven this expression we can return to Alex's quest
 
  *n=29679529859551692762820418740138329004315165131*
  
  Alex is now going to compute his n value, and after checking, he finds that it was divisible.
  
  $$2^n \equiv 2 (mod n)$$
  
  but ? is n a prime number? absolutely NOT because Fermat's theorem works only in this way ->
  
  
 if p is prime, then $$a^p \equiv a(mod p )$$
 
Last step gives us --> $$2^{341} \equiv 2 (mod 341)$$,  n = 341 and p = 341, 341 = 11.31


### Algorithm ###

1- If n is even or 1 < gcd(a,n) < n, return composite
2- write $$n-1 = 2^kq$$ with q odd
3- set a = a^q (mod n)
4- if $$a \equiv 1 (mod n)$$
5- loop i = 0,1,2,3,k-1
6- if $$a \equiv -1 (mod n)$$, return Test fails
7- set $$a = a^2 mod n$$
8- increment i and loop again step 5
9- return Composite
  
  
# Primality Rabin Test #

As we discuss earlier, for many cryptographic algorithm, it is important to select one or more very large prime numbers at random. Thus we are faced with the task of determining whether a given large number is prime. In this topic we will discuss how we can find whether n is prime or not with the help of **Primality Rabin Test**

## Miller-Rabin Algorithm

The algorithm deu to Miller and Rabin is typically used to test a large number for primality. Before explaining the algorithm, we need some background. First, any positive odd integer $n\geq 3$ can be expressed as:

$$n-1 = 2^k.q$$
    
In order to see whether is (n-1) is an even integer. Then we need to divide this by 2 until the result is odd number q.


Let me show you the algorithm of Miller-Rabin Test


1- Find integers k,q, k>0, q odd, so that $$(n-1) = 2^k.q$$
2- Select a random integer a, 1<a<n-1, if the first step is right.
3- if $$a^q.mod(n) = 1$$ then return("inconclusive");
4- for j = 0 to k-1 do
5- if $$a^{2/q}.mod n = n - 1$$ then return("inconclusive");
6- return("composite");


### Error bound ### 

I have shown The algorithm above briefly, now let me write the same expression of this method. We know that the expression is as follow:


> $$1\lt a\lt n-1$$     (random)


$$a^{n-1} - 1 = 0 mod ( n)$$

We can write this as --> $$(a^{n-1/2} -  1) x (a^{n-1/2} + 1) = 0 (mod n)$$

After that this one should be helpful --> $$(a^{n-1/4} -  1) x (a^{n-1/4} + 1) x (a^{n-1/2} + 1) = 0 (mod n)$$

-- > $$(a^{n-1/8} -  1) x (a^{n-1/8} + 1) x (a^{n-1/2} + 1) x (a^{n-1/4} + 1) x (a^{n-1/2} + 1) = 0 (mod n)$$


Oke, this will be enough. We will go further untill exponent is odd. 

 $$(a^{n-1/2^k} -  1) x (a^{n-1/2^k} + 1) x (a^{n-1/2} + 1)  = 0 (mod n)$$ 
 
 --> n should be divisible by $$2^k$$ when its prime if not, it does not have to divide into one of these terms
 
 
 I already mentioned about Euclid's lemma briefly. This fact is also called Euclid's lemma. We should not forget that n is randomly chosen by the input.
 
 When n is a prime and passed this test:
 
 1 - We have three-fourth probalility that n is actually prime
 
 2 - However, when n passes this test, we have one-fourth  probalility that n is composite.
 
 This means that this test is not perfect at all. It passes only 75 percent right ? actually No
 
 because when we choose 40 values of a, it means that the chance of being wrong goes to $$(1/4)^40$$, and this is very small chance of being wrong.
 
 That is equal to ---> $$(1/4)^{40} = 2^{-80}$$ probalility.


#### Code part of Miller Rabin prime test ####


I am going to show a code from [GeeksForGeeks](https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/?ref=gcse)


``` inline codeblock


// C# program Miller-Rabin primality test
using System;

class GFG
{

	// Utility function to do modular
	// exponentiation. It returns (x^y) % p
	static int power(int x, int y, int p)
	{
		
		int res = 1; // Initialize result
		
		// Update x if it is more than
		// or equal to p
		x = x % p;

		while (y > 0)
		{
			
			// If y is odd, multiply x with result
			if ((y & 1) == 1)
				res = (res * x) % p;
		
			// y must be even now
			y = y >> 1; // y = y/2
			x = (x * x) % p;
		}
		
		return res;
	}
	
	// This function is called for all k trials.
	// It returns false if n is composite and
	// returns false if n is probably prime.
	// d is an odd number such that d*2<sup>r</sup>
	// = n-1 for some r >= 1
	static bool miillerTest(int d, int n)
	{
		
		// Pick a random number in [2..n-2]
		// Corner cases make sure that n > 4
		Random r = new Random();
		int a = 2 + (int)(r.Next() % (n - 4));
	
		// Compute a^d % n
		int x = power(a, d, n);
	
		if (x == 1 || x == n - 1)
			return true;
	
		// Keep squaring x while one of the
		// following doesn't happen
		// (i) d does not reach n-1
		// (ii) (x^2) % n is not 1
		// (iii) (x^2) % n is not n-1
		while (d != n - 1)
		{
			x = (x * x) % n;
			d *= 2;
		
			if (x == 1)
				return false;
			if (x == n - 1)
				return true;
		}
	
		// Return composite
		return false;
	}
	
	// It returns false if n is composite
	// and returns true if n is probably
	// prime. k is an input parameter that
	// determines accuracy level. Higher
	// value of k indicates more accuracy.
	static bool isPrime(int n, int k)
	{
		
		// Corner cases
		if (n <= 1 || n == 4)
			return false;
		if (n <= 3)
			return true;
	
		// Find r such that n = 2^d * r + 1
		// for some r >= 1
		int d = n - 1;
		
		while (d % 2 == 0)
			d /= 2;
	
		// Iterate given number of 'k' times
		for (int i = 0; i < k; i++)
			if (miillerTest(d, n) == false)
				return false;
	
		return true;
	}
	
	// Driver Code
	static void Main()
	{
		int k = 4; // Number of iterations
	
		Console.WriteLine("All primes smaller " +
								"than 100: ");
								
		for (int n = 1; n < 100; n++)
			if (isPrime(n, k))
				Console.Write(n + " ");
	}
}

// This code is contributed by mits
 
```
#### Important ####

If you were unable to understand this mindset, please ask us for help... 




Thank you for spending your valuable time for this blog. I will see you in my next blog.





















