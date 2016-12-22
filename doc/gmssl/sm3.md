# SM3 Hash Algorithm

   The procedures are: Divide he message m' after padding into 512 bits
   blocks:


      m~ = B(0)B(1) ... B(n-1)             where n=(l+k+65)/512

   Apply iteration operation to m' as following:


      FOR i=0 TO n-1
          V (i+1) = CF(V (i);B(i))
      ENDFOR

   where CF is compression function, V(0) is a 256 bits of IVAGBPA[not]
   B(i) is a message block after padding, the result after iterative
   compression is V(n).



3.3.2.  Message Extension

   Divide the message block B(i) into 132 words, apply the words into
   the compression function:


   a) divide message block B(i) into 16 words W0, W1, ... , W15.
   b)   FOR j=16 TO 67
        Wj  < --  P1(WAGBPA"j-16AGBPA(C) XOR WAGBPA"j-9AGBPA(C) XOR (WAGBPA"j-3AGBPA(C)SHIFT15))
                  XOR (WAGBPA"j-13AGBPA(C)SHIFT7)  XOR WAGBPA"j-6AGBPA(C)
      ENDFOR
   c)   FOR j=0 TO 63
        Wj~ = Wj XOR W(j+4)
      ENDFOR
3.3.3.  Compression function

   Let A,B,C,D,E,F,G,H be registers to store words; SS1, SS2, TT1 and
   TT2 be intermediate variable; compression function:


                   V(i+1) = CF(V(i);B(i))          where 0 A!U i A!U n

   The computation precedures are as following:




Shen & Lee               Expires August 18, 2014                [Page 4]

Internet-Draft              SM3 Hash function              February 2014


                   ABCDEFGH  < --  V(i)
                   FOR j=0 TO 63
                           SS1  < --  ((A SHIFT12) + E + (Tj SHIFTj))?7
                           SS2  < --  SS1  XOR  (A SHIFT12)
                           TT1  < --  FFj(A,B,C) + D + SS2 +Wj~
                           TT1  < --  GGj(E,F,G) + H + SS1 +Wj
                           D  < --  C
                           C  < --  B SHIFT9
                           B  < --  A
                           A  < --  TT1
                           H  < --  G
                           G  < --  F SHIFT19
                           F  < --  E
                           E  < --  P0(TT2)
                   ENDFOR
                   V(i+1)  < --  ABCDEFGH  XOR  V (i)

   where a word is stored in memory as big-endian format.

3.3.4.  Hash Value

   ABCDEFGH < -- V(n)

   The 256 bits of hash value is y=ABCDEFGH.





## Test Vectors

"abc" 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0





61626364 61626364 61626364 61626364 61626364 61626364 61626364 61626364
 61626364 61626364 61626364 61626364 61626364 61626364 61626364 61626364



debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

