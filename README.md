# パスワードベース対称暗号化CLIツール

## 概要

このツールは、パスワードベースの暗号化・復号化を行うコマンドラインインターフェース（CLI）ツールです。指定したパスワードを使用してテキストやファイルを安全に暗号化・復号化できます。

## 特徴

- **パスワードベース対称暗号化**: 覚えやすいパスワードで暗号化
- **ファイル・テキスト対応**: 直接テキストまたはファイル全体を処理
- **標準入力対応**: パイプライン処理に対応
- **高セキュリティ**: PBKDF2とFernet暗号化を使用
- **クロスプラットフォーム**: Windows、macOS、Linuxで動作

## 制限事項
- UTF-8テキストファイルのみ対応
- 大ファイルは全メモリ読み込み
- パスワード保存・管理機能なし

## セットアップ
```bash
pip install cryptography
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
### 暗号化アルゴリズム
- **キー導出**: PBKDF2-HMAC-SHA256
- **イテレーション回数**: 100,000回
- **暗号化**: AES-128 (Fernet)
- **認証**: HMAC-SHA256

### セキュリティ機能
1. **ランダムsalt**: 各暗号化で16バイトのランダムsaltを生成
2. **認証付き暗号化**: データの完全性を保護
3. **安全なパスワード入力**: パスワードが画面に表示されない
4. **パスワード確認**: 暗号化時に誤入力を防ぐ

### データ形式
暗号化されたデータの構造：
```
[16バイトのsalt][暗号化されたデータ]
```

## バージョン情報

- **作成日**: 2025年5月
- **対応Python**: 3.6以上
- **依存ライブラリ**: cryptography