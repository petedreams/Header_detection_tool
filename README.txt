tkiwa
"特徴的なTCP/IPヘッダによるパケット検知ツール"

準備
1. パッケージ管理システムpipのインストール

get-pip.pyをダウンロードし、実行
$ sudo python get-pip.py

2. パケット解析モジュールdpktのインストール

$ sudo apt-get install python-dpkt (Ubuntuの場合)

セットアップ
tkiwa-2.x.tar.gzをダウンロード
$ tar xvf tkiwa-2.x.tar.gz
$ cd tkiwa-2.x
$ sudo pip install -e ./

使用方法
--version -バージョンを表示します

-h file -ヘルプメッセージを表示します

-r file -入力するpcapファイルを指定します

-v verbose -詳細な出力を表示します

-l, --line -一行表示で出力します

-t time -一行表示(-l)の場合、時間情報を追加します

-u, --update -[http://ipsr.ynu.ac.jp/tkiwa/signature.json] を取得し、最新のシグネチャに更新します

アンインストール
$ sudo pip uninstall tkiwa

作成者
横浜国立大学 小出 駿 (koide-takashi-mx@ynu.jp)
