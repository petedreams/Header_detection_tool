# headcap
"特徴的なTCP/IPヘッダによるパケット検知ツール"

##準備
#### 1. パッケージ管理システム[pip](https://pip.pypa.io/en/latest/index.html)のインストール
[get-pip.py](https://bootstrap.pypa.io/get-pip.py)をダウンロードし、実行  
```$ sudo python get-pip.py```
#### 2. パケット解析モジュール[dpkt](https://code.google.com/p/dpkt/)のインストール
```$ sudo apt-get install python-dpkt (Ubuntuの場合)```

##セットアップ
[headcap-1.0.tar.gz](http://ipsr.ynu.ac.jp/aaaa/headcap-1.0.tar.gz)をダウンロード  
```$ tar zxvf headcap-1.0.tar.gz```  
```$ cd headcap-1.0```  
```$ sudo pip install -e ./```  

##使用方法

  --version   -バージョンを表示します 

  -h file   -ヘルプメッセージを表示します 
  
  -r file   -入力するpcapファイルを指定します
  
  -v verbose   -詳細な出力を表示します
  
  -l, --line   -一行表示で出力します

  -t time   -一行表示(-l)の場合、時間情報を追加します
  
  -u, --update   -[http://ipsr.ynu.ac.jp/aaaa/signature.json] を取得し、最新のシグネチャを更新します

##アンインストール
```$ sudo pip uninstall headcap```

