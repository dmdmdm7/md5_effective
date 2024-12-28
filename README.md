# Проект

Программа эффективно перебирает все строки длины не более задаваемой, находя ту,  
которая имеет заданный MD5 хэш, передаваемый в параметрах к программе

# Запуск

Запустите исполняемый файл с параметрами:

1) При первом запуске программы:

md5.exe "your hash" "your path to config file"

2) Для продолжения перебора с конечной точки:

md5.exe resume

# Пример работы

1) Строка "abcababc" длины 8.

md5.exe 0e607524e08ebaa8295a030f50b9a976 C:/config.cfg

2) Продолжение с конечной точки

md5.exe resume
