## LAB2
ГОСТ 34.11 и ГОСТ Р 1323565.1.022-2018(вариант 4(Вторая конструкция выработки
промежуточного ключа))<br>
Реализована хэш-функция Стрибог и алгоритм диверсификации ключа на ее основе.<br>
Механизмы контроля аналогичны LAB1.<br>

Реализована функция kdf2 из ГОСТ Р 1323565.1.022-2018. <br>

В общем виде данной преобразование имеет такой вид.
![image](https://github.com/AllknowingOne/Cryptoprotocols/assets/45735331/68a27721-11e8-40c5-88e4-627b6448832a)
Параметры, от которых зависит функция могут разниться от реализации к реализации.<br>
В моем случае функция MAC(n) - это HMAC. Функция format принимает на вход несколько аргументов и конкатенирует их между собой. В моём случае format зависит от счетчика Ci, строки P(спецификация ключа(ключ шифрования)), строки U(username). <br>
Ключ для HMAC вычисляется функцией kdf1, на вход которой подается исходная ключевая информация S и соль T. <br>
![image](https://github.com/AllknowingOne/Cryptoprotocols/assets/45735331/54bd5b1e-3e9f-4944-8f74-32932a74e738)
<br>
В данном алгоритме есть большая свобода в настройке параметров. IV - вектор инициализации(нулевой в реализации). Функция существенно зависит от всех подаваемых параметров. <br>
HMAC<br>
![image](https://github.com/AllknowingOne/Cryptoprotocols/assets/45735331/c3979529-0394-4627-b425-f1ddc023a15e)
<br>
В качестве функции хэширования везде используется Streebog512.<br>
Алгоритм позволяет как тюнить параметры большим числом способов так и разными способами использовать саму функцию диверсификации. Например, можно строить уровни вложенности семейств диверсифицированных ключей или же просто пробегаться счетчиком и генерировать новые ключи.<br>

Время работы алгоритма при генерации 100000 ключей
![image](https://github.com/AllknowingOne/Cryptoprotocols/assets/45735331/a5c4d667-105c-4699-b4b8-cacda31bfdb5)<br>
Тест:<br>
![image](https://github.com/AllknowingOne/Cryptoprotocols/assets/45735331/e18352ab-e63f-46af-82e8-113f7f7276a1)