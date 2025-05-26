#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
パスワードベース暗号化・復号化CLIツール
指定したパスワードでファイルやテキストの暗号化・復号化を行います
"""

import os
import sys
import argparse
import getpass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64


class CryptoError(Exception):
    """暗号化・復号化に関するエラー"""
    pass


class PasswordCrypto:
    """パスワードベースの暗号化・復号化クラス"""

    def __init__(self, iterations=100000):
        """
        初期化

        Args:
            iterations (int): PBKDF2のイテレーション回数
        """
        self.iterations = iterations

    def _generate_key_from_password(self, password, salt):
        """
        パスワードとsaltから暗号化キーを生成

        Args:
            password (str): パスワード
            salt (bytes): salt（16バイト）

        Returns:
            bytes: 暗号化キー
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key

    def encrypt_text(self, plaintext, password):
        """
        テキストを暗号化

        Args:
            plaintext (str): 平文
            password (str): パスワード

        Returns:
            bytes: 暗号化されたデータ（salt + 暗号文）

        Raises:
            CryptoError: 暗号化に失敗した場合
        """
        try:
            # ランダムなsaltを生成
            salt = os.urandom(16)

            # パスワードからキーを生成
            key = self._generate_key_from_password(password, salt)

            # 暗号化
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(plaintext.encode('utf-8'))

            # saltと暗号化データを結合
            return salt + encrypted_data

        except Exception as e:
            raise CryptoError(f"暗号化に失敗しました: {e}")

    def decrypt_data(self, encrypted_data, password):
        """
        暗号化されたデータを復号化

        Args:
            encrypted_data (bytes): 暗号化されたデータ（salt + 暗号文）
            password (str): パスワード

        Returns:
            str: 復号化されたテキスト

        Raises:
            CryptoError: 復号化に失敗した場合
        """
        try:
            if len(encrypted_data) < 16:
                raise CryptoError("暗号化データが不正です（データが短すぎます）")

            # saltと暗号化データを分離
            salt = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # パスワードからキーを生成
            key = self._generate_key_from_password(password, salt)

            # 復号化
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(ciphertext)

            return decrypted_data.decode('utf-8')

        except Exception as e:
            if "Invalid token" in str(e):
                raise CryptoError("復号化に失敗しました: パスワードが間違っているか、データが破損しています")
            raise CryptoError(f"復号化に失敗しました: {e}")

    def encrypt_file(self, input_file_path, output_file_path, password):
        """
        ファイルを暗号化

        Args:
            input_file_path (str): 入力ファイルパス
            output_file_path (str): 出力ファイルパス
            password (str): パスワード

        Raises:
            CryptoError: 暗号化に失敗した場合
        """
        try:
            # ファイルを読み込み
            with open(input_file_path, 'r', encoding='utf-8') as f:
                plaintext = f.read()

            # 暗号化
            encrypted_data = self.encrypt_text(plaintext, password)

            # 暗号化データを保存
            with open(output_file_path, 'wb') as f:
                f.write(encrypted_data)

        except FileNotFoundError:
            raise CryptoError(f"入力ファイルが見つかりません: {input_file_path}")
        except UnicodeDecodeError:
            raise CryptoError(
                f"ファイルの読み込みに失敗しました: {input_file_path} （UTF-8以外のエンコーディングの可能性があります）")
        except Exception as e:
            raise CryptoError(f"ファイル暗号化に失敗しました: {e}")

    def decrypt_file(self, input_file_path, output_file_path, password):
        """
        ファイルを復号化

        Args:
            input_file_path (str): 入力ファイルパス（暗号化済み）
            output_file_path (str): 出力ファイルパス
            password (str): パスワード

        Raises:
            CryptoError: 復号化に失敗した場合
        """
        try:
            # 暗号化ファイルを読み込み
            with open(input_file_path, 'rb') as f:
                encrypted_data = f.read()

            # 復号化
            plaintext = self.decrypt_data(encrypted_data, password)

            # 復号化データを保存
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(plaintext)

        except FileNotFoundError:
            raise CryptoError(f"入力ファイルが見つかりません: {input_file_path}")
        except Exception as e:
            raise CryptoError(f"ファイル復号化に失敗しました: {e}")

    def decrypt_file_console(self, input_file_path, password) -> str:
        """
        ファイルを復号化

        Args:
            input_file_path (str): 入力ファイルパス（暗号化済み）
            password (str): パスワード

        Raises:
            CryptoError: 復号化に失敗した場合
        """
        try:
            # 暗号化ファイルを読み込み
            with open(input_file_path, 'rb') as f:
                encrypted_data = f.read()

            # 復号化
            plaintext = self.decrypt_data(encrypted_data, password)
            return plaintext


        except FileNotFoundError:
            raise CryptoError(f"入力ファイルが見つかりません: {input_file_path}")
        except Exception as e:
            raise CryptoError(f"ファイル復号化に失敗しました: {e}")


def get_secure_password(prompt="パスワードを入力してください: ", confirm=False, min_length=8):
    """
    パスワードを安全に入力（強度チェック付き）

    Args:
        prompt (str): 入力プロンプト
        confirm (bool): パスワード確認を行うか
        min_length (int): 最小長（デフォルト8文字）

    Returns:
        str: 入力されたパスワード

    Raises:
        CryptoError: パスワードが一致しない場合
    """
    # よく使われる脆弱なパスワードのリスト（一部）
    weak_passwords = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
        '1234567890', 'password1', '123456789', 'qwerty123'
    }

    while True:
        password = getpass.getpass(prompt)

        if not password:
            print("エラー: パスワードが空です", file=sys.stderr)
            continue

        if len(password) < min_length:
            print(f"エラー: パスワードは{min_length}文字以上にしてください", file=sys.stderr)
            continue

        # 脆弱なパスワードチェック
        if password.lower() in weak_passwords:
            print("エラー: そのパスワードは一般的すぎて危険です", file=sys.stderr)
            continue

        # パスワード強度チェック
        if confirm:
            has_lower = any(c.islower() for c in password)
            has_upper = any(c.isupper() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*(),.?\":{}|<>[]+=_-~`" for c in password)

            # 連続文字チェック
            has_sequence = False
            for i in range(len(password) - 2):
                if (ord(password[i + 1]) == ord(password[i]) + 1 and
                        ord(password[i + 2]) == ord(password[i]) + 2):
                    has_sequence = True
                    break

            # 繰り返し文字チェック
            has_repeat = False
            for i in range(len(password) - 2):
                if password[i] == password[i + 1] == password[i + 2]:
                    has_repeat = True
                    break

            strength_score = sum([has_lower, has_upper, has_digit, has_special])

            # 強度評価
            if strength_score < 3:
                print("警告: パスワードが弱いです。大文字、小文字、数字、記号を組み合わせてください。", file=sys.stderr)
            elif has_sequence:
                print("警告: 連続した文字の使用は避けてください（例: abc, 123）", file=sys.stderr)
            elif has_repeat:
                print("警告: 同じ文字の連続は避けてください（例: aaa, 111）", file=sys.stderr)

            if strength_score < 3 or has_sequence or has_repeat:
                if input("このパスワードを使用しますか？ (y/N): ").lower() != 'y':
                    continue

        if confirm:
            password_confirm = getpass.getpass("パスワードを再入力してください: ")
            if password != password_confirm:
                print("エラー: パスワードが一致しません", file=sys.stderr)
                # 確認用パスワードをメモリから消去
                password_confirm = '\x00' * len(password_confirm)
                continue
            # 確認用パスワードをメモリから消去
            password_confirm = '\x00' * len(password_confirm)

        return password


def encrypt_command(args):
    """暗号化コマンドの実行"""
    crypto = PasswordCrypto()

    try:
        # パスワード入力
        password = get_secure_password("暗号化用パスワードを入力してください: ", confirm=True)

        if args.text:
            # テキストを直接暗号化
            encrypted_data = crypto.encrypt_text(args.text, password)

            if args.output:
                # ファイルに保存
                with open(args.output, 'wb') as f:
                    f.write(encrypted_data)
                print(f"暗号化完了: {args.output}")
            else:
                # Base64エンコードして表示
                encoded_data = base64.b64encode(encrypted_data).decode('ascii')
                print("暗号化されたデータ (Base64):")
                print(encoded_data)

        elif args.file:
            # ファイルを暗号化
            output_file = args.output or f"{args.file}.encrypted"
            crypto.encrypt_file(args.file, output_file, password)
            print(f"ファイル暗号化完了: {args.file} -> {output_file}")

        else:
            # 標準入力からテキストを読み込み
            print("暗号化するテキストを入力してください (Ctrl+D で終了):")
            try:
                text = sys.stdin.read().strip()
                if not text:
                    raise CryptoError("入力テキストが空です")

                encrypted_data = crypto.encrypt_text(text, password)

                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(encrypted_data)
                    print(f"暗号化完了: {args.output}")
                else:
                    encoded_data = base64.b64encode(encrypted_data).decode('ascii')
                    print("暗号化されたデータ (Base64):")
                    print(encoded_data)

            except EOFError:
                raise CryptoError("テキストの入力が中断されました")

    except KeyboardInterrupt:
        print("\n操作がキャンセルされました", file=sys.stderr)
        sys.exit(1)


def decrypt_command(args):
    """復号化コマンドの実行"""
    crypto = PasswordCrypto()

    try:
        # パスワード入力
        password = get_secure_password("復号化用パスワードを入力してください: ")

        if args.data:
            # Base64データを直接復号化
            try:
                encrypted_data = base64.b64decode(args.data)
            except Exception:
                raise CryptoError("無効なBase64データです")

            plaintext = crypto.decrypt_data(encrypted_data, password)

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(plaintext)
                print(f"復号化完了: {args.output}")
            else:
                print("復号化されたテキスト:")
                print("-" * 40)
                print(plaintext)
                print("-" * 40)

        elif args.file:
            # ファイルを復号化
            if args.output:
                output_file = args.output or f"{args.file}.decrypted"
                crypto.decrypt_file(args.file, output_file, password)
                print(f"ファイル復号化完了: {args.file} -> {output_file}")
            else:
                plaintext = crypto.decrypt_file_console(args.file, password)
                print(f"復号化されたファイル: {plaintext}")


        else:
            raise CryptoError("復号化するデータまたはファイルを指定してください")

    except KeyboardInterrupt:
        print("\n操作がキャンセルされました", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='パスワードベース暗号化・復号化CLIツール',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # テキストを暗号化 (コンソール出力)
  python crypto_cli.py encrypt -t "秘密のメッセージ"

  # テキストを暗号化 (ファイル出力)
  python crypto_cli.py encrypt -t "秘密のメッセージ" -o document.encrypted

  # ファイルを暗号化
  python crypto_cli.py encrypt -f document.txt -o document.encrypted

  # 標準入力から暗号化
  python crypto_cli.py encrypt -o encrypted.bin

  # Base64データを復号化
  python crypto_cli.py decrypt -d "gAAAAABh..."

  # ファイルを復号化 (コンソール出力)
  python crypto_cli.py decrypt -f document.encrypted

  # ファイルを復号化 (ファイル出力)
  python crypto_cli.py decrypt -f document.encrypted -o document.txt
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='使用可能なコマンド')

    # 暗号化コマンド
    encrypt_parser = subparsers.add_parser('encrypt', help='データを暗号化')
    encrypt_group = encrypt_parser.add_mutually_exclusive_group()
    encrypt_group.add_argument('-t', '--text', type=str, help='暗号化するテキスト')
    encrypt_group.add_argument('-f', '--file', type=str, help='暗号化するファイル')
    encrypt_parser.add_argument('-o', '--output', type=str, help='出力ファイル名')

    # 復号化コマンド
    decrypt_parser = subparsers.add_parser('decrypt', help='データを復号化')
    decrypt_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    decrypt_group.add_argument('-d', '--data', type=str, help='復号化するBase64データ')
    decrypt_group.add_argument('-f', '--file', type=str, help='復号化するファイル')
    decrypt_parser.add_argument('-o', '--output', type=str, help='出力ファイル名')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == 'encrypt':
            encrypt_command(args)
        elif args.command == 'decrypt':
            decrypt_command(args)

    except CryptoError as e:
        print(f"エラー: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"予期しないエラー: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
