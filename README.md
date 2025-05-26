# パスワードベース対称暗号化CLIツール

## 概要

このツールは、Argon2による安全なパスワードベースの暗号化・復号化を行うコマンドラインインターフェース（CLI）ツールです。指定したパスワードを用いて、テキストまたはファイルを安全に処理できます。

## 特徴

- **Argon2パスワードベース鍵導出**: 高セキュリティなKDF（RFC 9106準拠）
- **AES-256-CBC暗号化**: 強力な対称鍵暗号
- **HMAC-SHA256による整合性検証**
- **ファイル・テキスト・標準入力に対応**
- **クロスプラットフォーム**

## 制限事項
- UTF-8テキストファイルのみ対応
- パスワード保存・管理機能なし

## セットアップ
```bash
pip install -r requirements.txt
```

## 使用方法

### コマンド構文
```
python crypto_cli.py <command> [options]
```

### 利用可能なコマンド
- `encrypt`: データを暗号化
- `decrypt`: データを復号化

## ヘルプ表示
```bash
python crypto_cli.py --help
python crypto_cli.py encrypt --help
python crypto_cli.py decrypt --help
```

## オプション一覧

### 暗号化 (encrypt)
| オプション | 短縮形 | 説明 | 必須 |
|-----------|--------|------|------|
| `--text` | `-t` | 暗号化するテキストを直接指定 | - |
| `--file` | `-f` | 暗号化するファイルのパス | - |
| `--output` | `-o` | 出力ファイル名 | - |

```bash
# テキストを直接暗号化
python crypto_cli.py encrypt -t "秘密のメッセージ"

# ファイルを暗号化
python crypto_cli.py encrypt -f input.txt -o output.encrypted
python crypto_cli.py encrypt -f input.txt  # 自動で input.txt.encrypted に出力

# 標準入力から暗号化
echo "データ" | python crypto_cli.py encrypt -o encrypted.bin
```

**実行例:**
```bash
$ python crypto_cli.py encrypt -f secret.txt -o secret.encrypted
暗号化用パスワードを入力してください: 
パスワードを再入力してください: 
ファイル暗号化完了: secret.txt -> secret.encrypted
```


### 復号化 (decrypt)
| オプション | 短縮形 | 説明 | 必須 |
|-----------|--------|------|------|
| `--data` | `-d` | 復号化するBase64データ | ※1 |
| `--file` | `-f` | 復号化するファイルのパス | ※1 |
| `--output` | `-o` | 出力ファイル名 | - |

※1 `--data`または`--file`のいずれかが必須

```bash
# Base64データを復号化
python crypto_cli.py decrypt -d "gAAAAABhpqL4..."

# ファイルを復号化
python crypto_cli.py decrypt -f document.decrypted -o output.txt
python crypto_cli.py decrypt -f document.decrypted  # コンソール上にのみ復号文を出力
```

**実行例:**
```bash
$ python crypto_cli.py decrypt -d "gAAAAABhpqL4..."
復号化用パスワードを入力してください: 
復号化されたテキスト:
----------------------------------------
これは秘密のメッセージです
----------------------------------------
```

## 応用例

### パイプライン処理
```bash
ls -la | python crypto_cli.py encrypt -o list.encrypted
python crypto_cli.py decrypt -f list.encrypted
```

### 複数ファイル処理
```bash
for file in *.txt; do
    python crypto_cli.py encrypt -f "$file" -o "${file}.encrypted"
done
```

## セキュリティ仕様

### 🔐 使用アルゴリズムとパラメータ

| 項目             | 内容                                      |
|------------------|-------------------------------------------|
| 鍵導出関数        | Argon2id（RFC 9106準拠）                  |
| 時間コスト        | 3                                         |
| メモリコスト      | 64MB（65536 KiB）                         |
| 並列度            | 4                                         |
| 暗号化アルゴリズム | AES-256-CBC                               |
| ハッシュ検証      | HMAC-SHA256（鍵付きハッシュ）             |
| salt サイズ       | 32バイト                                  |
| IV（初期化ベクトル）| 16バイト                                  |
| HMAC サイズ       | 32バイト                                  |

### 🛡️ セキュリティ機能

- **ランダム salt & IV**: 暗号化ごとに新たに生成されるためリプレイ攻撃を防止
- **認証付き暗号化**: HMAC により改ざん検知を実現
- **パスワード入力確認**: 暗号化時は2回入力で誤入力を防止
- **整合性チェック**: 復号時にHMAC検証を行い、失敗時は即座にエラー

### 📦 暗号化ファイルの構造

```
[SALT (32B)][IV (16B)][暗号文][HMAC (32B)]
```

## バージョン情報

- **作成日**: 2025年5月
- **対応Python**: 3.6以上
- **依存ライブラリ**: cryptography, argon2-cffi

※旧バージョンをご利用したい方はブランチを"v0"に切り替えてください。