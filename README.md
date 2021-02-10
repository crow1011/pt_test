# Запуск

```sh
python3 main.py data/allow.list data/deny.list  -o rep.lst -p
```

- -p переключает вывод на только 24 и 32 маски(Отключен по умолчанию)
- -o задает путь сохранения отчета(по умолчанию ./report.list)
- -h справка

## Запуск тестов

```sh
python3 -m unittest tests/full_test.py
```