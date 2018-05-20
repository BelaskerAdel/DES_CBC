# DES_CBC
This is a python script for encryption and decryption using the Data Encryption Standard (DES) algorithm in the Cipher Block Chaining (CBC) mode of operation .
##Examples :
Encrypt the text="Adel Belasker" in CBC mode with the KEY="1f4f8a113b4a5d66" with initial vector IV=[0]*40+[1]*20+[0]*4 :

``` cypher_text=CBC_DES_ENC(IV,text,KEY)```
Decryction:

```original_text=CBC_DES_DEC(IV,cypher_text,KEY)```

## Documentation :
For further details about how DES works , read this <a href="http://highered.mheducation.com/sites/dl/free/007070208x/877405/Chapter_06_Data_Encription_Standard.pdf"> [PDF] </a> .
and to learn about CBC mode , please visit this<a href="https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode"> [link]</a> . 


### Author :
Adel Belasker<br/>
E-mail : adel.belasker@gmail.com <br/>
Linkedin : https://www.linkedin.com/in/belasker/




