#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Argon2パスワードベース暗号化・復号化CLIツール
指定したパスワードでファイルやテキストの暗号化・復号化を行います
"""

import sys
import argparse
import getpass
import secrets
import hmac
import hashlib
import time
from pathlib import Path
import argon2

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64


class CryptoError(Exception):
    """暗号化・復号化に関するエラー"""
    pass


class SecurePasswordCrypto:
    """Argon2パスワードベースの暗号化・復号化クラス"""

    # セキュリティパラメータ
    # Argon2パラメータ (RFC 9106推奨値)
    ARGON2_TIME_COST = 3  # 時間コスト（反復回数）
    ARGON2_MEMORY_COST = 65536  # メモリコスト（KiB）= 64MB
    ARGON2_PARALLELISM = 4  # 並列度
    ARGON2_HASH_LEN = 64  # ハッシュ長（暗号化キー32バイト + HMACキー32バイト）

    # 従来のKDFパラメータ（互換性維持用）
    SALT_SIZE = 32  # saltサイズを16から32バイトに増加
    KEY_SIZE = 32  # AES-256用のキーサイズ
    IV_SIZE = 16  # AES CBCモードのIVサイズ
    HMAC_SIZE = 32  # SHA-256 HMACのサイズ

    # ファイル形式のマジックナンバーとバージョン
    MAGIC = b'SECENC'
    VERSION = 2  # Argon2対応でバージョンアップ

    # KDF種別定数
    KDF_ARGON2ID = 2
    KDF_ARGON2I = 1
    KDF_ARGON2D = 0

    def __init__(self, kdf_type='argon2id', argon2_variant='id'):  # 64MB
        """
        初期化

        Args:
            kdf_type (str): 'argon2id', 'argon2i', 'argon2d'
            argon2_variant (str): Argon2のバリアント ('id', 'i', 'd')
        """
        self.kdf_type = kdf_type
        self.argon2_variant = argon2_variant

    def _secure_random(self, size):
        """暗号学的に安全な乱数生成"""
        return secrets.token_bytes(size)

    def _derive_keys_argon2(self, password, salt, variant='id'):
        """
        Argon2を使用してパスワードとsaltから暗号化キーとHMACキーを導出

        Args:
            password (str): パスワード
            salt (bytes): salt
            variant (str): Argon2のバリアント ('id', 'i', 'd')

        Returns:
            tuple: (暗号化キー, HMACキー)
        """
        # パスワードを正規化（NFKC）して一貫性を保つ
        import unicodedata
        normalized_password = unicodedata.normalize('NFKC', password)
        password_bytes = normalized_password.encode('utf-8')

        # Argon2バリアントの選択
        if variant == 'id':
            # Argon2id: ハイブリッド版（推奨）
            argon2.PasswordHasher(
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=self.ARGON2_HASH_LEN,
                salt_len=len(salt),
                type=argon2.Type.ID
            )
        elif variant == 'i':
            # Argon2i: データ独立版（サイドチャネル攻撃耐性）
            argon2.PasswordHasher(
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=self.ARGON2_HASH_LEN,
                salt_len=len(salt),
                type=argon2.Type.I
            )
        elif variant == 'd':
            # Argon2d: データ依存版（GPU攻撃耐性が高い）
            argon2.PasswordHasher(
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=self.ARGON2_HASH_LEN,
                salt_len=len(salt),
                type=argon2.Type.D
            )
        else:
            raise CryptoError(f"サポートされていないArgon2バリアント: {variant}")

        # 低レベルAPIを使用してカスタムsaltでハッシュ生成
        from argon2.low_level import hash_secret_raw

        # Argon2タイプの決定
        if variant == 'id':
            argon2_type = argon2.Type.ID
        elif variant == 'i':
            argon2_type = argon2.Type.I
        else:  # 'd'
            argon2_type = argon2.Type.D

        derived = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
            hash_len=self.ARGON2_HASH_LEN,
            type=argon2_type
        )

        # キーを分割
        encryption_key = derived[:self.KEY_SIZE]
        hmac_key = derived[self.KEY_SIZE:]

        return encryption_key, hmac_key

    def _get_kdf_flag(self):
        """KDF種別のフラグを取得"""
        if self.kdf_type == 'argon2id':
            return self.KDF_ARGON2ID
        elif self.kdf_type == 'argon2i':
            return self.KDF_ARGON2I
        elif self.kdf_type == 'argon2d':
            return self.KDF_ARGON2D
        else:
            return self.KDF_ARGON2ID  # デフォルト

    def _kdf_from_flag(self, flag):
        """フラグからKDF種別を取得"""
        if flag == self.KDF_ARGON2ID:
            return 'argon2id'
        elif flag == self.KDF_ARGON2I:
            return 'argon2i'
        elif flag == self.KDF_ARGON2D:
            return 'argon2d'
        else:
            return 'argon2id'  # デフォルト

    def _create_header(self, salt, iv):
        """暗号化ファイルのヘッダーを作成"""
        header = bytearray()
        header.extend(self.MAGIC)
        header.append(self.VERSION)
        header.append(self._get_kdf_flag())  # KDF種別
        header.extend(salt)
        header.extend(iv)
        return bytes(header)

    def _parse_header(self, data):
        """暗号化ファイルのヘッダーを解析"""
        if len(data) < len(self.MAGIC) + 2 + self.SALT_SIZE + self.IV_SIZE:
            raise CryptoError("暗号化データが不正です（ヘッダーが短すぎます）")

        offset = 0

        # マジックナンバー確認
        magic = data[offset:offset + len(self.MAGIC)]
        if magic != self.MAGIC:
            raise CryptoError("不正な暗号化ファイル形式です")
        offset += len(self.MAGIC)

        # バージョン確認
        version = data[offset]
        if version not in [1, 2]:  # バージョン1（旧版）とバージョン2（Argon2対応版）をサポート
            raise CryptoError(f"サポートされていないファイルバージョンです: {version}")
        offset += 1

        # KDF種別
        kdf_flag = data[offset]
        used_kdf = self._kdf_from_flag(kdf_flag)
        offset += 1

        # Salt
        salt = data[offset:offset + self.SALT_SIZE]
        offset += self.SALT_SIZE

        # IV
        iv = data[offset:offset + self.IV_SIZE]
        offset += self.IV_SIZE

        return salt, iv, used_kdf, offset

    def encrypt_text(self, plaintext, password):
        """
        テキストを暗号化（認証付き暗号化）

        Args:
            plaintext (str): 平文
            password (str): パスワード

        Returns:
            bytes: 暗号化されたデータ（ヘッダー + 暗号文 + HMAC）

        Raises:
            CryptoError: 暗号化に失敗した場合
        """
        try:
            # ランダムなsaltとIVを生成
            salt = self._secure_random(self.SALT_SIZE)
            iv = self._secure_random(self.IV_SIZE)

            # パスワードからキーを導出
            encryption_key, hmac_key = self._derive_keys_argon2(password, salt)

            # 平文をパディング
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode('utf-8'))
            padded_data += padder.finalize()

            # AES-256-CBCで暗号化
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # ヘッダーを作成
            header = self._create_header(salt, iv)

            # HMACを計算（ヘッダー + 暗号文）
            h = hmac.new(hmac_key, header + ciphertext, hashlib.sha256)
            mac = h.digest()

            # 最終データを結合
            return header + ciphertext + mac

        except Exception as e:
            # メモリ内の機密データをクリア
            if 'encryption_key' in locals():
                encryption_key = b'\x00' * len(encryption_key)
            raise CryptoError(f"暗号化に失敗しました: {e}")

    def decrypt_data(self, encrypted_data, password):
        """
        暗号化されたデータを復号化（認証確認付き）

        Args:
            encrypted_data (bytes): 暗号化されたデータ
            password (str): パスワード

        Returns:
            str: 復号化されたテキスト

        Raises:
            CryptoError: 復号化に失敗した場合
        """
        try:
            # ヘッダーを解析
            salt, iv, used_kdf, header_size = self._parse_header(encrypted_data)

            # 使用されたKDF種別を設定
            original_kdf = self.kdf_type
            self.kdf_type = used_kdf

            # HMACとciphertextを分離
            if len(encrypted_data) < header_size + self.HMAC_SIZE:
                raise CryptoError("暗号化データが不正です（データが短すぎます）")

            ciphertext = encrypted_data[header_size:-self.HMAC_SIZE]
            received_mac = encrypted_data[-self.HMAC_SIZE:]

            # パスワードからキーを導出
            encryption_key, hmac_key = self._derive_keys_argon2(password, salt)

            # HMAC検証
            expected_mac = hmac.new(
                hmac_key,
                encrypted_data[:-self.HMAC_SIZE],
                hashlib.sha256
            ).digest()

            if not hmac.compare_digest(received_mac, expected_mac):
                raise CryptoError(
                    "データの整合性チェックに失敗しました（パスワードが間違っているか、データが改ざんされています）")

            # 復号化
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # パディング除去
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # KDF設定を復元
            self.kdf_type = original_kdf

            return plaintext.decode('utf-8')

        except Exception as e:
            # メモリ内の機密データをクリア
            if 'encryption_key' in locals():
                encryption_key = b'\x00' * len(encryption_key)

            if "データの整合性チェックに失敗" in str(e):
                raise CryptoError(str(e))
            raise CryptoError(f"復号化に失敗しました: {e}")

    def encrypt_file(self, input_file_path, output_file_path, password):
        """
        ファイルを暗号化（大きなファイル対応）

        Args:
            input_file_path (str): 入力ファイルパス
            output_file_path (str): 出力ファイルパス
            password (str): パスワード

        Raises:
            CryptoError: 暗号化に失敗した場合
        """
        try:
            input_path = Path(input_file_path)
            if not input_path.exists():
                raise CryptoError(f"入力ファイルが見つかりません: {input_file_path}")

            # ファイルサイズチェック
            file_size = input_path.stat().st_size
            if file_size > 100 * 1024 * 1024:  # 100MB制限
                raise CryptoError("ファイルサイズが大きすぎます（100MB以下にしてください）")

            # ファイルを読み込み
            with open(input_file_path, 'rb') as f:
                file_data = f.read()

            # バイナリデータをBase64エンコードして暗号化
            # これによりバイナリファイルも扱える
            try:
                # まずUTF-8として試す
                text_data = file_data.decode('utf-8')
            except UnicodeDecodeError:
                # バイナリファイルの場合はBase64エンコード
                text_data = base64.b64encode(file_data).decode('ascii')
                text_data = f"BINARY:{text_data}"

            # 暗号化
            encrypted_data = self.encrypt_text(text_data, password)

            # 暗号化データを保存
            with open(output_file_path, 'wb') as f:
                f.write(encrypted_data)

        except Exception as e:
            if isinstance(e, CryptoError):
                raise
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
            decrypted_text = self.decrypt_data(encrypted_data, password)

            # バイナリファイルかどうか判断
            if decrypted_text.startswith("BINARY:"):
                # Base64デコードしてバイナリデータに戻す
                base64_data = decrypted_text[7:]  # "BINARY:"を除去
                file_data = base64.b64decode(base64_data)
                mode = 'wb'
            else:
                # テキストファイル
                file_data = decrypted_text.encode('utf-8')
                mode = 'wb'

            # 復号化データを保存
            with open(output_file_path, mode) as f:
                f.write(file_data)

        except Exception as e:
            if isinstance(e, CryptoError):
                raise
            raise CryptoError(f"ファイル復号化に失敗しました: {e}")

    def decrypt_file_console(self, input_file_path, password) -> str:
        """
        ファイルを復号化してコンソールに表示

        Args:
            input_file_path (str): 入力ファイルパス（暗号化済み）
            password (str): パスワード

        Returns:
            str: 復号化されたテキスト

        Raises:
            CryptoError: 復号化に失敗した場合
        """
        try:
            # 暗号化ファイルを読み込み
            with open(input_file_path, 'rb') as f:
                encrypted_data = f.read()

            # 復号化
            plaintext = self.decrypt_data(encrypted_data, password)

            if plaintext.startswith("BINARY:"):
                raise CryptoError("バイナリファイルはコンソール出力できません。-o オプションでファイル出力してください。")

            return plaintext

        except Exception as e:
            if isinstance(e, CryptoError):
                raise
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
    # KDF選択
    kdf_type = "argon2id"
    if args.argon2d:
        kdf_type = "argon2d"
    elif args.argon2i:
        kdf_type = "argon2i"

    crypto = SecurePasswordCrypto(kdf_type=kdf_type)

    try:
        # パスワード入力
        password = get_secure_password("暗号化用パスワードを入力してください: ", confirm=True)

        if args.text:
            # テキストを直接暗号化
            print("暗号化中...")
            start_time = time.time()
            encrypted_data = crypto.encrypt_text(args.text, password)
            end_time = time.time()

            if args.output:
                # ファイルに保存
                with open(args.output, 'wb') as f:
                    f.write(encrypted_data)
                print(f"暗号化完了: {args.output} ({end_time - start_time:.2f}秒)")
            else:
                # Base64エンコードして表示
                encoded_data = base64.b64encode(encrypted_data).decode('ascii')
                print("暗号化されたデータ (Base64):")
                print(encoded_data)
                print(f"処理時間: {end_time - start_time:.2f}秒")

        elif args.file:
            # ファイルを暗号化
            output_file = args.output or f"{args.file}.encrypted"
            print("ファイル暗号化中...")
            start_time = time.time()
            crypto.encrypt_file(args.file, output_file, password)
            end_time = time.time()
            print(f"ファイル暗号化完了: {args.file} -> {output_file} ({end_time - start_time:.2f}秒)")

        else:
            # 標準入力からテキストを読み込み
            print("暗号化するテキストを入力してください (Ctrl+D で終了):")
            try:
                text = sys.stdin.read().strip()
                if not text:
                    raise CryptoError("入力テキストが空です")

                print("暗号化中...")
                start_time = time.time()
                encrypted_data = crypto.encrypt_text(text, password)
                end_time = time.time()

                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(encrypted_data)
                    print(f"暗号化完了: {args.output} ({end_time - start_time:.2f}秒)")
                else:
                    encoded_data = base64.b64encode(encrypted_data).decode('ascii')
                    print("暗号化されたデータ (Base64):")
                    print(encoded_data)
                    print(f"処理時間: {end_time - start_time:.2f}秒")

            except EOFError:
                raise CryptoError("テキストの入力が中断されました")

    except KeyboardInterrupt:
        print("\n操作がキャンセルされました", file=sys.stderr)
        sys.exit(1)


def decrypt_command(args):
    """復号化コマンドの実行"""
    crypto = SecurePasswordCrypto()  # KDF種別は暗号化ファイルから自動判別

    try:
        # パスワード入力
        password = get_secure_password("復号化用パスワードを入力してください: ")

        if args.data:
            # Base64データを直接復号化
            try:
                encrypted_data = base64.b64decode(args.data)
            except Exception:
                raise CryptoError("無効なBase64データです")

            print("復号化中...")
            start_time = time.time()
            plaintext = crypto.decrypt_data(encrypted_data, password)
            end_time = time.time()

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(plaintext)
                print(f"復号化完了: {args.output} ({end_time - start_time:.2f}秒)")
            else:
                print("復号化されたテキスト:")
                print("-" * 40)
                print(plaintext)
                print("-" * 40)
                print(f"処理時間: {end_time - start_time:.2f}秒")

        elif args.file:
            # ファイルを復号化
            if args.output:
                output_file = args.output
                print("ファイル復号化中...")
                start_time = time.time()
                crypto.decrypt_file(args.file, output_file, password)
                end_time = time.time()
                print(f"ファイル復号化完了: {args.file} -> {output_file} ({end_time - start_time:.2f}秒)")
            else:
                print("復号化中...")
                start_time = time.time()
                plaintext = crypto.decrypt_file_console(args.file, password)
                end_time = time.time()
                print("復号化されたファイル内容:")
                print("-" * 40)
                print(plaintext)
                print("-" * 40)
                print(f"処理時間: {end_time - start_time:.2f}秒")

        else:
            raise CryptoError("復号化するデータまたはファイルを指定してください")

    except KeyboardInterrupt:
        print("\n操作がキャンセルされました", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Argon2版パスワードベース暗号化・復号化CLIツール',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
セキュリティ機能:
  • AES-256-CBC暗号化 + HMAC-SHA256認証
  • Argon2による安全なキー導出
  • 暗号学的に安全な乱数生成
  • パスワード強度チェック
  • データ整合性検証
  • バイナリファイル対応

使用例:
  # テキストをArgon2で暗号化
  python crypto_cli.py encrypt -t "秘密のメッセージ"

  # ファイルを暗号化
  python crypto_cli.py encrypt -f document.txt -o document.encrypted

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
    encrypt_parser.add_argument('--argon2i', action='store_true',
                                help='Argon2iを使用(デフォルトはArgon2id)')
    encrypt_parser.add_argument('--argon2d', action='store_true',
                                help='Argon2dを使用(デフォルトはArgon2id)')

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
