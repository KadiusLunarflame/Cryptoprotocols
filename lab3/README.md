В качестве источника псевдорандомной последовательности используется поточный алгоритм шифрования ChaCha20.\
RFC: https://datatracker.ietf.org/doc/html/rfc7539#page-4 
Значение для nonce следует брать из хорошего источника энтропии(dev/random подойдет). Опционально можно и значение ключа делать случайным и генерировать хорошие последовательности.\
Тесты NIST дают хорошие результаты:
![img.png](img.png)
Последовательность размером 16M проходит все тесты.