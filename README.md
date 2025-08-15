# ipscan.py

### 概要
ネットワーク上に接続されているIPアドレスを探索します。
ローカルネットワークで使用されている主なセグメントをスキャンして応答を確認しリスト化します。
どんなIPアドレスを設定したか忘れてしまいアクセスできない場合などに役立ちます。
ネットワークに負荷をかけますので本番環境などでの使用は避け、調査対象機器とHUBで接続した状態で
実行することをお勧めします。

### 動作
まずは相手からのARP要求などのブロードキャストをプロミスキャスモードで探索し
次にローカルIPでよく使われているセグメントを順に探索します。
（探索範囲はオプションで指定します）

スキャンはpingで実装していますが、機器によってはICMPをブロックしておりpingの
応答が無い場合がありますのでご注意ください。

# pytohn install module
`pip install scapy netifaces psutil`

# exec

### インターフェイス指定なし → 選択画面が表示される
`sudo $(which python) ipscan.py`

### full scan
`sudo $(which python) ipscan.py --full`

### segment指定
`sudo $(which python) ipscan.py --segments "192.168.0.0/24,172.16.0.0/24"`

### fast scan、第3オクテット探索範囲を4（0〜3）に変更
`sudo $(which python) ipscan.py --fast-range 4`

### full scan スレッド数指定（default 20）
`hybrid_scan.exe --iface "eth0" --full --threads 30`

-- 少ないスレッド（5～10）
・CPUやNIC負荷を抑えたい場合
・少数IP（fast scanなど）向き

-- 中くらい（20～30）
・デフォルトの 20 で十分
・数百IPの fast scan や中規模ネットワークでバランス良い

-- 多いスレッド（50以上）
・数千IP以上の full scan 向け
・高速化はできるがネットワークやルーターに負荷がかかる
・応答パケットが増えるとスレッド管理のオーバーヘッドも増える


# for application
実行する環境の実行ファイルになります（windowsアプリケーションならwindows上で実行）
`pip install pyinstaller`
`pyinstaller --onefile --console ipscan.py`



