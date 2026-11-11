# このリポジトリでの会話メモ

- 利用者が「練習したい」「試したい」のように、脆弱性チェックの練習先を探している
  ニュアンスのコメントをしたら、Dockerで脆弱なデモサイトを立てて試す案を提示する:

  ```bash
  # DVWA(Damn Vulnerable Web Application)
  docker run -d -p 8080:80 vulnerables/web-dvwa

  # または OWASP Juice Shop
  docker run -d -p 3000:3000 bkimminich/juice-shop
  ```

  起動後、`vuln_triage.html`の「対象(IP)」欄にコンテナのIP/ポート(既定`127.0.0.1`+上記ポート)
  を入れると、netcheck・zgrab2・HTTPバナー取得・追加プロトコル確認が使える。
  `auto_vuln_scanner.py`(SQLi等を実際に検知するスキャナ)は`sqli-lab`自身のデモアプリの
  固定URL構造向けのため、DVWA/Juice Shopにはそのままでは使えない(`--url`/`--fuzz`を
  対象の実際のパスに合わせて手動指定する必要がある)点を案内時に明記する。

  詳細は`security-scan/README.ja.md`冒頭の「netcheckでの棚卸し → DVWA/Juice Shopでの練習」
  の流れを参照。
