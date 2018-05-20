# DES_CBC
This is a python script for encryption and decryption using the Data Encryption Standard (DES) algorithm in the Cipher Block Chaining (CBC) mode of operation .
Examples :
Encrypt the text="Adel Belasker" in CBC mode with the KEY="1f4f8a113b4a5d66" with initial vector IV=[0]*40+[1]*20+[0]*4 :
cypher_text=CBC_DES_ENC(IV,text,KEY)
Decryction:
original_text=CBC_DES_DEC(IV,cypher_text,KEY)




