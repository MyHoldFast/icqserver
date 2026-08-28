# icqserver

ICQ/OSCAR-сервер на Go, протокол реверс-инжинирили, референсом был iserverd.

## Сборка

```
go mod tidy
go build -o icqserver .
./icqserver
```

`adduser` — отдельная утилита (Python 3) для создания пользователя напрямую в БД:

```
chmod +x adduser

# рядом с icq_server.db
./adduser 123456 secret

# с ником
./adduser 123456 secret --nick Vasya

# другая БД
./adduser 123456 secret --db /path/to/icq_server.db

# сменить пароль существующему
./adduser 123456 newpass --force
```

## Поддерживается

Регистрация, plain/XOR и MD5-логин, SSI/ростер (группы, контакты, privacy, авторизация), присутствие, сообщения + "печатает", анкета, поиск (детали/UIN/UTF8), офлайн-сообщения.

## Отличия от iserverd

Починены типичные его болячки: xstatus меняется мгновенно, офлайн-сообщения доходят целиком, а не обрезанными, в нике и анкете теперь можно писать кириллицей — и по мелочи ещё много чего.

## Проверено

ICQ2003, QIP 2005, Jimm, D[i]Chat, Jasmine, Miranda — работает.
ICQ 5.1 Lite — частичная поддержка.

---

# icqserver (English)

An ICQ/OSCAR server in Go — the protocol was reverse-engineered, with iserverd as the reference.

## Build

```
go mod tidy
go build -o icqserver .
./icqserver
```

`adduser` — a standalone Python 3 utility to create a user directly in the DB:

```
chmod +x adduser

# next to icq_server.db
./adduser 123456 secret

# with a nickname
./adduser 123456 secret --nick Vasya

# a different DB
./adduser 123456 secret --db /path/to/icq_server.db

# change an existing user's password
./adduser 123456 newpass --force
```

## Supported

Registration, plain/XOR and MD5 login, SSI/roster (groups, contacts, privacy, auth requests), presence, messaging + typing, profile, search (details/UIN/UTF8), offline messages.

## Differences from iserverd

Fixes a bunch of its usual pain points: xstatus updates instantly, offline messages arrive intact instead of getting cut off, nicknames and profiles can now be written in Cyrillic — plus a good number of smaller fixes.

## Verified

ICQ2003, QIP 2005, Jimm, D[i]Chat, Jasmine, Miranda — working.
ICQ 5.1 Lite — partial support.