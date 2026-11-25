# Автоматический переход с домена на RD Web в IIS

Выбор страницы в Studio формирует адрес открытия портала. Для перехода с `https://rds.example.org/` на `/RDWeb/` либо `/RDWeb/webclient/` при сквозном TLS настройте редирект **на Windows/IIS**. HAProxy в этой схеме не видит HTTP-путь внутри TLS.

До изменения откройте выбранный конечный путь напрямую. Если `/RDWeb/webclient/` отвечает 404, проверьте установку HTML5 Web Client на Windows: одно перенаправление не создаёт отсутствующий клиент.

## Правило через IIS Manager

Нужен установленный Microsoft IIS URL Rewrite. На Windows-сервере:

1. Откройте **IIS Manager** и выберите **сайт, внутри которого находится приложение RDWeb** (часто `Default Web Site`). Правило задаётся на уровне сайта, не внутри приложения RDWeb.
2. Откройте **URL Rewrite → Add Rule(s) → Blank rule**.
3. Название: `RDWeb root redirect`. Requested URL: **Matches the Pattern**. Using: **Regular Expressions**. Pattern: **`^$`**.
4. В **Conditions** выберите **Match All** и добавьте:

| Input | Pattern | Назначение |
| --- | --- | --- |
| `{HTTP_HOST}` | `^rds\.example\.org(?::443)?$` | Только нужное публичное имя; замените домен своим и экранируйте точки |
| `{REQUEST_URI}` | `^/(?:\?.*)?$` | Только исходный корень `/`, в том числе с query string |
| `{REQUEST_METHOD}` | `^(GET|HEAD)$` | Только открытие страницы; POST и другие методы не перенаправляются |

5. Action type: **Redirect**. Redirect URL: **`https://rds.example.org/RDWeb/`** (с вашим доменом). Для установленного HTML5-клиента: `https://rds.example.org/RDWeb/webclient/`.
6. Redirect type: **Found (302)**. Append query string: **включено**. Stop processing subsequent rules: **включено**, если это поле доступно.
7. Нажмите **Apply** и проверьте сначала корень сайта, затем прямой адрес `/RDWeb/`. Правило не соответствует `/RDWeb/`, `/rpc/` или `/remoteDesktopGateway/`, поэтому не направляет их обратно на портал.

Это точечное правило. Не заменяйте его широким редиректом всех путей сайта, не изменяйте настройки дочерних приложений и не заменяйте существующий `web.config` целиком. Перед правкой можно сохранить резервную копию конфигурации IIS; если работает администратор, стандартная команда:

```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" add backup "Before-RDWeb-RootRedirect"
```

Перезапуск всего IIS через `iisreset` для добавления правила не требуется. Если URL Rewrite отсутствует, сначала установите соответствующий модуль Microsoft; XML секции `rewrite` без модуля добавлять нельзя.

## Проверка результата

Корень должен возвращать `302` с заголовком `Location` на выбранный полный URL. После перехода уже IIS/RDWeb может выполнять свои перенаправления на страницы входа. Сам путь портала не должен попадать в цикл перенаправления. Для отмены отключите либо удалите только правило `RDWeb root redirect`.

Для нестандартного публичного порта укажите его в адресе назначения и условии Host. Если несколько публичных доменов обслуживают один сайт, добавляйте правила осознанно для нужных имён: приведённый вариант применяется только к одному домену.

Основание: [Microsoft — URL Rewrite Module Configuration Reference](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference) описывает область действия правил, сопоставление относительного пути, условия по переменным HTTP и действие Redirect.
