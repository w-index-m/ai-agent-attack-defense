# deck

`build_deck.js` (Japanese) and `build_deck_en.js` (English) generate the 37-slide decks with pptxgenjs (`npm i pptxgenjs`).
They load a theme helper from `/mnt/skills/public/pptx/scripts/apply_theme.js`, which exists only in the original authoring environment; to run elsewhere, remove the `applyTheme` import/calls or supply your own. The generated decks are included: `AI_agent_attack_tools_analysis.pptx` (JP) and `AI_agent_attack_tools_analysis_EN.pptx` (EN).

## `sqli-types-and-techniques.pptx`

SQLインジェクションの8分類(認証バイパス・エラーベース・UNIONベース・ブラインド真偽値・ブラインド時間・
セカンドオーダー・スタック済みクエリ・Out-of-band)と、各手口の入力例・検出の目印をまとめたスライド(19→21枚)。
`build_deck.js`では生成していない、別系統の手作りデッキ。

- 13枚目「JUICE SHOPでの実践」・14枚目(スクリーンショット): OWASP Juice Shop(練習用の公開デモアプリ、
  `docker run -d -p 3000:3000 bkimminich/juice-shop`で自分のPC上に起動)に対し、①認証バイパス・②エラーベースを
  実際に確認した記録(2026-11-27)。③UNIONベースは列数当てに着手した段階で、実機確認は未完了。
- `auto_vuln_scanner.py --class sqli`は、sqli-labの`/login`専用の判定文言(`login ok`等)を前提にしているため、
  Juice Shopではヒットしても「status code changed (200→500)」という汎用判定のみになる(個別の手口の判別は未対応)。
  実際にSQLエラーが漏れていることの確認は、`curl`でレスポンス本文を直接見て行った(`SQLITE_ERROR: incomplete input`)。
- 詳細: `security-scan/sqli-lab-coverage.ja.md`の「8分類との対応」の節。
