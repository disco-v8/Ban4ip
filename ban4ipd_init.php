<?php
// ------------------------------------------------------------
// 
// BAN for iptables/ip6tables
// 
// T.Kabu/MyDNS.JP           http://www.MyDNS.JP/
// Future Versatile Group    http://www.fvg-on.net/
// 
// ------------------------------------------------------------
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function local_time()
{
    global $TIME_OFFSET;
    return(time() + $TIME_OFFSET);
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function psearch($PP, $PATTERN)
{
    // リソース$PPから一行ずつ読み込む
    while (($DATA = fgets($PP)) !== false)
    {
        // もし$DATA内に$PATTERNに該当するデータがあるなら
        if (preg_match($PATTERN, rtrim($DATA)))
        {
            // TRUEを返す
            return TRUE;
        }
    }
    // 見つからなければ、FALSEを返す
    return FALSE;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function psearch2($PP, $PATTERN)
{
    // リソース$PPから一行ずつ読み込む
    while (($DATA = fgets($PP)) !== false)
    {
        // もし$DATA内に$PATTERNに該当するデータがあるなら
        if (preg_match($PATTERN, rtrim($DATA), $MATCH, PREG_UNMATCHED_AS_NULL))
        {
            // $MATCHを返す
            return $MATCH;
        }
    }
    // 見つからなければ、FALSEを返す
    return FALSE;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function log_write($BAN4IPD_CONF)
{
    // ログファイルの指定がないなら
    if (!isset($BAN4IPD_CONF['log_file']) || !is_file($BAN4IPD_CONF['log_file']))
    {
        print $BAN4IPD_CONF['log_msg'];
        return;
    }
    
    // ログファイルポインタが開かれていないなら
    if (!isset($BAN4IPD_CONF['log_p']))
    {
        $BAN4IPD_CONF['log_p'] = fopen($BAN4IPD_CONF['log_file'], 'a');
    }
    // ログファイルポインタが開かれているなら
    if (is_resource($BAN4IPD_CONF['log_p']))
    {
        // ログファイルを排他的ロック
        while(!flock($BAN4IPD_CONF['log_p'], LOCK_EX));
        // ログファイルの一番最後までシーク
        fseek($BAN4IPD_CONF['log_p'], 0, SEEK_END);
        // ログファイルに書き出し
        fprintf($BAN4IPD_CONF['log_p'], $BAN4IPD_CONF['log_msg']);
        // ログファイルをアンロック
        flock($BAN4IPD_CONF['log_p'], LOCK_UN);
    }
    else
    {
        print $BAN4IPD_CONF['log_msg'];
    }
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbreset_sqlite3()
{
    global $BAN4IPD_CONF;
    
    // SQLite3のデータベースファイルを削除
    @unlink($BAN4IPD_CONF['db_dir'].'/ban.db');
    @unlink($BAN4IPD_CONF['db_dir'].'/count.db');
    @unlink($BAN4IPD_CONF['db_dir'].'/mailrate.db');
    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: SQLite3's DB File deleted."."\n";
    // ログに出力する
    log_write($BAN4IPD_CONF);

    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ban4ip will be RESTART!"."\n";
    // ログに出力する
    log_write($BAN4IPD_CONF);
    // サービスを再起動する
    system('/usr/bin/ban4ipc restart');
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_sqlite3_count_db()
{
    global $BAN4IPD_CONF;
    
    // SQLite3データベース用のディレクトリを作成(エラー出力を抑制)
    @mkdir($BAN4IPD_CONF['db_dir']);
    // SQLite3データベース用のディレクトリがないなら
    if (!is_dir($BAN4IPD_CONF['db_dir']))
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['db_dir']." not found!?"."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // カウントデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['count_db']) && $BAN4IPD_CONF['count_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['count_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // カウントデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['count_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_count']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_count']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['count_db']->exec('CREATE TABLE IF NOT EXISTS count_tbl (address, service, registdate)');
    // インデックスを作成する
    $BAN4IPD_CONF['count_db']->exec('CREATE INDEX IF NOT EXISTS count_idx ON count_tbl (address)');
    
    // journal_modeをWALにする
    $BAN4IPD_CONF['count_db']->exec('PRAGMA journal_mode=WAL');
    // synchronousをNORMALにする
    $BAN4IPD_CONF['count_db']->exec('PRAGMA synchronous=NORMAL');
    
    // カウントデータベースのロックタイムアウト時間を少し長くする
    $BAN4IPD_CONF['count_db']->exec('PRAGMA busy_timeout='.$BAN4IPD_CONF['db_timeout']);
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_sqlite3_ban_db()
{
    global $BAN4IPD_CONF;
    
    // SQLite3データベース用のディレクトリを作成(エラー出力を抑制)
    @mkdir($BAN4IPD_CONF['db_dir']);
    // SQLite3データベース用のディレクトリがないなら
    if (!is_dir($BAN4IPD_CONF['db_dir']))
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['db_dir']." not found!?"."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // BANデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['ban_db']) && $BAN4IPD_CONF['ban_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['ban_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // BANデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['ban_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_ban']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_ban']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['ban_db']->exec('CREATE TABLE IF NOT EXISTS ban_tbl (address, service, protcol, port, rule, unbandate)');
    // インデックスを作成する
    $BAN4IPD_CONF['ban_db']->exec('CREATE INDEX IF NOT EXISTS ban_idx ON ban_tbl (address)');
    
    // journal_modeをWALにする
    $BAN4IPD_CONF['ban_db']->exec('PRAGMA journal_mode=WAL');
    // synchronousをNORMALにする
    $BAN4IPD_CONF['ban_db']->exec('PRAGMA synchronous=NORMAL');
    
    // BANデータベースのロックタイムアウト時間を少し長くする
    $BAN4IPD_CONF['ban_db']->exec('PRAGMA busy_timeout='.$BAN4IPD_CONF['db_timeout']);
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_sqlite3_mailrate_db()
{
    global $BAN4IPD_CONF;
    
    // SQLite3データベース用のディレクトリを作成(エラー出力を抑制)
    @mkdir($BAN4IPD_CONF['db_dir']);
    // SQLite3データベース用のディレクトリがないなら
    if (!is_dir($BAN4IPD_CONF['db_dir']))
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['db_dir']." not found!?"."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // メール送信レートテーブルデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['mailrate_db']) && $BAN4IPD_CONF['mailrate_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['mailrate_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // メール送信レートテーブルデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['mailrate_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_mailrate']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_mailrate']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['mailrate_db']->exec('CREATE TABLE IF NOT EXISTS mailrate_tbl (to_address, title, registdate, UNIQUE (to_address, title) )');
    // インデックスを作成する
    $BAN4IPD_CONF['mailrate_db']->exec('CREATE INDEX IF NOT EXISTS mailrate_idx ON mailrate_tbl (to_address, title)');
    
    // journal_modeをWALにする
    $BAN4IPD_CONF['mailrate_db']->exec('PRAGMA journal_mode=WAL');
    // synchronousをNORMALにする
    $BAN4IPD_CONF['mailrate_db']->exec('PRAGMA synchronous=NORMAL');
    
    // メール送信レートテーブルデータベースのロックタイムアウト時間を少し長くする
    $BAN4IPD_CONF['mailrate_db']->exec('PRAGMA busy_timeout='.$BAN4IPD_CONF['db_timeout']);
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_pgsql_count_db()
{
    global $BAN4IPD_CONF;
    
    // カウントデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['count_db']) && $BAN4IPD_CONF['count_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['count_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // カウントデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['count_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_count']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_count']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['count_db']->exec('CREATE TABLE IF NOT EXISTS count_tbl (address varchar(48), service varchar(128), registdate bigint)');
    // インデックスを作成する
    $BAN4IPD_CONF['count_db']->exec('CREATE INDEX IF NOT EXISTS count_idx ON count_tbl (address)');
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_pgsql_ban_db()
{
    global $BAN4IPD_CONF;
    
    // BANデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['ban_db']) && $BAN4IPD_CONF['ban_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['ban_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // BANデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['ban_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_ban']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_ban']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['ban_db']->exec('CREATE TABLE IF NOT EXISTS ban_tbl (address varchar(48), service varchar(128), protcol varchar(88), port varchar(8), rule varchar(8), unbandate bigint)');
    // インデックスを作成する
    $BAN4IPD_CONF['ban_db']->exec('CREATE INDEX IF NOT EXISTS ban_idx ON ban_tbl (address)');
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_pgsql_mailrate_db()
{
    global $BAN4IPD_CONF;
    
    // メール送信レートテーブルデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['mailrate_db']) && $BAN4IPD_CONF['mailrate_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['mailrate_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // メール送信レートテーブルデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['mailrate_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_mailrate']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_mailrate']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['mailrate_db']->exec('CREATE TABLE IF NOT EXISTS mailrate_tbl (to_address varchar(128), title varchar(128), registdate bigint, UNIQUE (to_address, title) )');
    // インデックスを作成する
    $BAN4IPD_CONF['mailrate_db']->exec('CREATE INDEX IF NOT EXISTS mailrate_idx ON mailrate_tbl (to_address, title)');
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_mysql_count_db()
{
    global $BAN4IPD_CONF;
    
    // カウントデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['count_db']) && $BAN4IPD_CONF['count_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['count_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // カウントデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['count_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_count'], $BAN4IPD_CONF['pdo_dsn_username'], $BAN4IPD_CONF['pdo_dsn_password']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_count']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['count_db']->exec('CREATE TABLE IF NOT EXISTS count_tbl (address varchar(48), service varchar(128), registdate bigint)');
    // インデックスがあっても無くても作成する
    try
    {
        $BAN4IPD_CONF['count_db']->exec('ALTER TABLE count_tbl ADD INDEX count_idx (address)');
    }
    // 何からの理由でインデックスを作成できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        // …が、特に気にしない(性能は落ちるかもしれないけど)
    }
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_mysql_ban_db()
{
    global $BAN4IPD_CONF;
    
    // BANデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['ban_db']) && $BAN4IPD_CONF['ban_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['ban_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // BANデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['ban_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_ban'], $BAN4IPD_CONF['pdo_dsn_username'], $BAN4IPD_CONF['pdo_dsn_password']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_ban']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['ban_db']->exec('CREATE TABLE IF NOT EXISTS ban_tbl (address varchar(48), service varchar(128), protcol varchar(88), port varchar(8), rule varchar(8), unbandate bigint)');
    // インデックスがあっても無くても作成する
    try
    {
        $BAN4IPD_CONF['ban_db']->exec('ALTER TABLE ban_tbl ADD INDEX ban_idx (address)');
    }
    // 何からの理由でインデックスを作成できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        // …が、特に気にしない(性能は落ちるかもしれないけど)
    }
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit_mysql_mailrate_db()
{
    global $BAN4IPD_CONF;
    
    // メール送信レートテーブルデータベースがすでに接続されていたら
    if (isset($BAN4IPD_CONF['mailrate_db']) && $BAN4IPD_CONF['mailrate_db'] != null)
    {
        // いったん切断
        $BAN4IPD_CONF['mailrate_db'] = null;
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    // メール送信レートテーブルデータベースに接続を試す
    try
    {
        $BAN4IPD_CONF['mailrate_db'] = new PDO($BAN4IPD_CONF['pdo_dsn_mailrate'], $BAN4IPD_CONF['pdo_dsn_username'], $BAN4IPD_CONF['pdo_dsn_password']);
    }
    // 接続できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_mailrate']." not Connection!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // テーブルがなかったら作成
    $BAN4IPD_CONF['mailrate_db']->exec('CREATE TABLE IF NOT EXISTS mailrate_tbl (to_address varchar(128), title varchar(128), registdate bigint, UNIQUE (to_address, title) )');
    // インデックスがあっても無くても作成する
    try
    {
        $BAN4IPD_CONF['mailrate_db']->exec('ALTER TABLE mailrate_tbl ADD INDEX mailrate_idx (to_address, title)');
    }
    // 何からの理由でインデックスを作成できなかったら(失敗した場合、 PDOException を投げてくる)
    catch(PDOException $e)
    {
        // …が、特に気にしない(性能は落ちるかもしれないけど)
    }
    
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbinit()
{
    global $BAN4IPD_CONF;
    
    // ----------------
    // カウントデータベースのデータソース名(DSN)の指定がなければ、
    // ----------------
    if (empty($BAN4IPD_CONF['pdo_dsn_count']))
    {
        // カウントデータベースに接続(無ければ新規に作成)
        $BAN4IPD_CONF['pdo_dsn_count'] = 'sqlite:' . $BAN4IPD_CONF['db_dir'].'/count.db';
    }
    
    // ----------------
    // BANデータベースのデータソース名(DSN)の指定がなければ、
    // ----------------
    if (empty($BAN4IPD_CONF['pdo_dsn_ban']))
    {
        // BANデータベースに接続(無ければ新規に作成)
        $BAN4IPD_CONF['pdo_dsn_ban'] = 'sqlite:' . $BAN4IPD_CONF['db_dir'].'/ban.db';
    }
    
    // ----------------
    // メール送信レートデータベースのデータソース名(DSN)の指定がなければ、
    // ----------------
    if (empty($BAN4IPD_CONF['pdo_dsn_mailrate']))
    {
        // メール送信レートテーブルデータベースに接続(無ければ新規に作成)
        $BAN4IPD_CONF['pdo_dsn_mailrate'] = 'sqlite:' . $BAN4IPD_CONF['db_dir'].'/mailrate.db';
    }
    
    // ----------------
    // カウントデータベースのデータソース名(DSN)の指定により初期化処理分岐
    // ----------------
    // カウントデータベースのデータソース名(DSN)の指定が「pgsql」なら
    if (isset($BAN4IPD_CONF['pdo_dsn_count']) && preg_match('/^pgsql/', $BAN4IPD_CONF['pdo_dsn_count']))
    {
        // カウントデータベースの初期化処理
        ban4ip_dbinit_pgsql_count_db();
    }
    // カウントデータベースのデータソース名(DSN)の指定が「mysql」なら
    else if (isset($BAN4IPD_CONF['pdo_dsn_count']) && isset($BAN4IPD_CONF['pdo_dsn_username']) && isset($BAN4IPD_CONF['pdo_dsn_password']) && preg_match('/^mysql/', $BAN4IPD_CONF['pdo_dsn_count']))
    {
        // カウントデータベースの初期化処理
        ban4ip_dbinit_mysql_count_db();
    }
    // カウントデータベースのデータソース名(DSN)の指定が「sqlite」なら
    else if (isset($BAN4IPD_CONF['pdo_dsn_count']) && preg_match('/^sqlite/', $BAN4IPD_CONF['pdo_dsn_count']))
    {
        // カウントデータベースの初期化処理
        ban4ip_dbinit_sqlite3_count_db();
    }
    // カウントデータベースのデータソース名(DSN)の指定が上記以外なら
    else
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_count'].", not supported!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // ----------------
    // BANデータベースのデータソース名(DSN)の指定により初期化処理分岐
    // ----------------
    // BANデータベースのデータソース名(DSN)の指定が「pgsql」なら
    if (isset($BAN4IPD_CONF['pdo_dsn_ban']) && preg_match('/^pgsql/', $BAN4IPD_CONF['pdo_dsn_ban']))
    {
        // BANデータベースの初期化処理
        ban4ip_dbinit_pgsql_ban_db();
    }
    // BANデータベースのデータソース名(DSN)の指定が「mysql」なら
    else if (isset($BAN4IPD_CONF['pdo_dsn_ban']) && isset($BAN4IPD_CONF['pdo_dsn_username']) && isset($BAN4IPD_CONF['pdo_dsn_password']) && preg_match('/^mysql/', $BAN4IPD_CONF['pdo_dsn_ban']))
    {
        // BANデータベースの初期化処理
        ban4ip_dbinit_mysql_ban_db();
    }
    // BANデータベースのデータソース名(DSN)の指定が「sqlite」なら
    else if (isset($BAN4IPD_CONF['pdo_dsn_ban']) && preg_match('/^sqlite/', $BAN4IPD_CONF['pdo_dsn_ban']))
    {
        // BANデータベースの初期化処理
        ban4ip_dbinit_sqlite3_ban_db();
    }
    // BANデータベースのデータソース名(DSN)の指定が上記以外なら
    else
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_ban'].", not supported!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // ----------------
    // メール送信レートデータベースのデータソース名(DSN)の指定により初期化処理分岐
    // ----------------
    // メール送信レートデータベースのデータソース名(DSN)の指定が「pgsql」なら
    if (isset($BAN4IPD_CONF['pdo_dsn_mailrate']) && preg_match('/^pgsql/', $BAN4IPD_CONF['pdo_dsn_mailrate']))
    {
        // メール送信レートデータベースの初期化処理
        ban4ip_dbinit_pgsql_mailrate_db();
    }
    // メール送信レートデータベースのデータソース名(DSN)の指定が「mysql」なら
    else if (isset($BAN4IPD_CONF['pdo_dsn_mailrate']) && isset($BAN4IPD_CONF['pdo_dsn_username']) && isset($BAN4IPD_CONF['pdo_dsn_password']) && preg_match('/^mysql/', $BAN4IPD_CONF['pdo_dsn_mailrate']))
    {
        // メール送信レートデータベースの初期化処理
        ban4ip_dbinit_mysql_mailrate_db();
    }
    // メール送信レートデータベースのデータソース名(DSN)の指定が「sqlite」なら
    else if (isset($BAN4IPD_CONF['pdo_dsn_mailrate']) && preg_match('/^sqlite/', $BAN4IPD_CONF['pdo_dsn_mailrate']))
    {
        // メール送信レートデータベースの初期化処理
        ban4ip_dbinit_sqlite3_mailrate_db();
    }
    // メール送信レートデータベースのデータソース名(DSN)の指定が上記以外なら
    else
    {
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR ".$BAN4IPD_CONF['pdo_dsn_mailrate'].", not supported!? ".$e->getMessage()."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        // 終わり
        exit -1;
    }
    
    // ----------------
    // 情報共有サーバー関連のパにより初期化処理分岐
    // ----------------
    // 情報共有フラグがON(=1)なら
    if (isset($BAN4IPD_CONF['iss_flag']) && $BAN4IPD_CONF['iss_flag'] == 1)
    {
        // 情報共有サーバー名が設定されていないなら
        if (!isset($BAN4IPD_CONF['iss_server']))
        {
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR iss_server is not set!?"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // 終わり
            exit -1;
        }
        // 情報共有サーバーへ接続するユーザー名が設定されていないなら
        if (!isset($BAN4IPD_CONF['iss_username']))
        {
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR iss_username is not set!?"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // 終わり
            exit -1;
        }
        // 情報共有サーバーへ接続するユーザー名のパスワードが設定されていないなら
        if (!isset($BAN4IPD_CONF['iss_password']))
        {
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR iss_password is not set!?"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // 終わり
            exit -1;
        }
        
        // BAN情報取得秒数(現在時刻よりiss_get_time[秒]前までのデータを取得する)がおかしい場合には
        if (!isset($BAN4IPD_CONF['iss_get_time']) || !is_numeric($BAN4IPD_CONF['iss_get_time']))
        {
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR iss_get_time(".$BAN4IPD_CONF['iss_get_time'].")"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // 終わり
            exit -1;
        }
        // BAN情報取得数(最大iss_get_limit[個]のデータを取得する)がおかしい場合には
        if (!isset($BAN4IPD_CONF['iss_get_limit']) || !is_numeric($BAN4IPD_CONF['iss_get_limit']))
        {
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR iss_get_limit(".$BAN4IPD_CONF['iss_get_limit'].")"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // 終わり
            exit -1;
        }
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Init Routine
// ----------------------------------------------------------------------
// 環境変数などを設定する
// 時刻オフセット初期化
$TIME_OFFSET = 0;

// Cannot find timezone
if (ini_get('date.timezone') == FALSE)
{
    // Set system timezone to UTC
    date_default_timezone_set(@date_default_timezone_get());
    
    // Get system time
    exec("/bin/date +'%Y/%m/%d %H:%M:%S'", $EXEC_RESULT, $EXEC_RETVAL);
    // Complete
    if ($EXEC_RETVAL == 0)
    {
        // Get difference between the values of system time and PHP time
        $TIME_OFFSET = strtotime($EXEC_RESULT[0]) - time();
        
        // Set offset time if it is more than 60sec
        if ($TIME_OFFSET && ($TIME_OFFSET % 60) == 0)
        {
        }
        else if ($TIME_OFFSET > 0)
        {
            // Set time offset in minutes
            $TIME_OFFSET += (60 - ($TIME_OFFSET % 60));
        }
        else if ($TIME_OFFSET < 0)
        {
            // Set time offset in minutes
            $TIME_OFFSET -= ($TIME_OFFSET % 60);
        }
    }
}

// 内部文字コード
mb_internal_encoding('UTF-8');

// 出力文字コード
mb_http_output('UTF-8');

// メイン設定ファイル名
$BAN4IPD_CONF['main_conf'] = '/etc/ban4ipd.conf';

?>
<?php
// ----------------------------------------------------------------------
// Check inotify module
// ----------------------------------------------------------------------
// inotifyモジュールがあるか確認
if (!extension_loaded('inotify'))
{
    print "inotify extension not loaded!?"."\n";
    exit -1;
}
?>
<?php
// ----------------------------------------------------------------------
// Check sqlite module
// ----------------------------------------------------------------------
// sqlite3モジュールがあるか確認
if (!extension_loaded('sqlite3'))
{
    print "sqlite3 extension not loaded!?"."\n";
    // 終わり
    exit -1;
}
?>
<?php
// ----------------------------------------------------------------------
// Check pdo_sqlite module
// ----------------------------------------------------------------------
// pdo_sqliteモジュールがあるか確認
if (!extension_loaded('pdo_sqlite'))
{
    print "pdo_sqlite extension not loaded!?"."\n";
    // 終わり
    exit -1;
}
?>
<?php
// ----------------------------------------------------------------------
// Check sockets module
// ----------------------------------------------------------------------
// socketsモジュールがあるか確認
if (!extension_loaded('sockets'))
{
    print "sockets extension not loaded!?"."\n";
    // 終わり
    exit -1;
}
?>
<?php
// ----------------------------------------------------------------------
// Read Configration
// ----------------------------------------------------------------------
// メイン設定ファイルがあるなら
if (is_file($BAN4IPD_CONF['main_conf']))
{
    // メイン設定ファイルを読み込んで変数展開する
    $BAN4IPD_CONF = parse_ini_file($BAN4IPD_CONF['main_conf'], FALSE, INI_SCANNER_NORMAL);
}
// 無ければ、
else
{
    print $BAN4IPD_CONF['main_conf']." not found!?"."\n";
    // 終わり
    exit -1;
}
// 読み込めなかったら
if ($BAN4IPD_CONF === FALSE)
{
    print "Cannot loaded main config file!?"."\n";
    // 終わり
    exit -1;
}
?>
<?php
// ----------------------------------------------------------------------
// Get init or systemd
// ----------------------------------------------------------------------
// システムがinit管理かsystemd管理かを取得
$BAN4IPD_CONF['system_pid0'] = file_get_contents('/proc/1/comm');
$BAN4IPD_CONF['system_pid0'] = rtrim($BAN4IPD_CONF['system_pid0']);
?>
