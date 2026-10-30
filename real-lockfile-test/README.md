# 実物のロックファイルでの OSV 実通信の確認用（main には入れない）

`uv lock` / `poetry lock` / `go mod tidy` / `dotnet restore` が実際に生成したファイル。
**意図的に古い（脆弱な）版**を含む：jinja2 2.10、requests 2.19.0、golang.org/x/text 0.3.6、Newtonsoft.Json 12.0.1。
CI の照合や Trivy が警告を出し続けるため、main には入れず、確認が済んだら、このフォルダごと消す。

リポジトリのルートで実行（それぞれ、既知の脆弱性が 1 件以上出れば成功）:

    python scripts/dep_cve_check.py --uv-lock real-lockfile-test/uv.lock --out uv.sarif
    python scripts/dep_cve_check.py --poetry-lock real-lockfile-test/poetry.lock --out poetry.sarif
    python scripts/dep_cve_check.py --go-sum real-lockfile-test/go.sum --out go.sarif
    python scripts/dep_cve_check.py --nuget-lock real-lockfile-test/packages.lock.json --out nuget.sarif
