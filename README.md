PHP Dead Code Reporter
=====================

eBPFを使用してPHPのコンパイルイベントを監視し、実行されているファイルを追跡するツールです。

## 概要

このプロジェクトは、USDT（User-level Statically Defined Tracing）プローブを使用してPHPのコンパイルイベントを追跡します。eBPFプログラムがカーネル空間で実行され、コンパイルされたPHPファイルの情報をBPF MAPに保存します。Goアプリケーションは定期的にこのマップを読み取り、統計情報を表示します。

## 必要要件

### システム要件
- Linux カーネル 5.4 以降（eBPF CO-RE サポート）
- root権限

### ソフトウェア要件
- Go 1.19 以降
- clang 10 以降
- libbpf
- bpftool
- Linux headers

### Ubuntu/Debianでのインストール
```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool
```

### RHEL/CentOS/Fedoraでのインストール
```bash
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    bpftool
```

## ビルド方法

1. リポジトリをクローン:
```bash
git clone <repository-url>
cd php-dcr
```

2. 依存関係を取得:
```bash
go mod download
```

3. ビルド:
```bash
make build
```

これにより以下が実行されます:
- `vmlinux.h` の生成（カーネルBTFから）
- eBPFプログラムのコンパイル (`bpf/php.bpf.o`)
- Goバイナリのビルド (`php-dcr`)

## 使用方法

1. プログラムを実行（root権限が必要）:
```bash
sudo ./php-dcr
```

または:
```bash
sudo make run
```

2. プログラムは5秒ごとにPHPコンパイルファイルの統計情報を表示します:
```
=== PHP Compile File Statistics ===
Filename                                                     Count
-----------------------------------------------------------
/var/www/html/index.php                                      42
/var/www/html/config.php                                     15
...

Total unique files: 2
```

3. 終了するには `Ctrl+C` を押してください

## プロジェクト構成

```
.
├── bpf/
│   ├── php.bpf.c        # eBPFプログラム（USDTプローブ）
│   ├── maps.bpf.h       # BPF MAPヘルパー関数
│   └── vmlinux.h        # カーネル型定義（自動生成）
├── main.go              # Goローダーとマップリーダー
├── Makefile             # ビルドスクリプト
├── go.mod               # Go依存関係
└── README.md            # このファイル
```

## 仕組み

1. **eBPFプログラム** (`bpf/php.bpf.c`):
   - PHPの `compile__file__entry` USDTプローブにアタッチ
   - コンパイルされたファイル名をキャプチャ
   - LRU HASHマップ `php_compile_file_total` にカウントを保存

2. **Goプログラム** (`main.go`):
   - eBPFオブジェクトファイルをロード
   - USDTプローブをアタッチ
   - 5秒ごとにBPF MAPを読み取り
   - ファイル名とコンパイルカウントを表示

## カスタマイズ

### PHPライブラリパスの変更

`main.go`の以下の行を環境に合わせて修正してください:
```go
_, err = prog.AttachUSDT(-1, "/usr/lib/apache2/modules/libphp8.1.so", "php", "compile__file__entry")
```

### ポーリング間隔の変更

`main.go`の以下の行でポーリング間隔を調整できます:
```go
ticker := time.NewTicker(5 * time.Second)  // 5秒から好きな値に変更
```

## トラブルシューティング

### eBPFプログラムのロードに失敗する
- root権限で実行していることを確認
- カーネルがeBPF CO-REをサポートしていることを確認（5.4以降）
- BTFが有効になっていることを確認: `ls /sys/kernel/btf/vmlinux`

### USDTプローブのアタッチに失敗する
- PHPライブラリのパスが正しいことを確認
- PHPがUSDTサポート付きでビルドされていることを確認
- 利用可能なプローブを確認: `sudo bpftool probe | grep php`

### データが表示されない
- PHPアプリケーションが実際に実行されていることを確認
- PHPがファイルをコンパイルしていることを確認（opcacheがキャッシュしている可能性）

## クリーンアップ

ビルド成果物を削除:
```bash
make clean
```

## ライセンス

GPL
