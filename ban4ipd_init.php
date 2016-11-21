<?php
// ------------------------------------------------------------
// 
// BAN for IP
// 
// T.Kabu/MyDNS.JP           http://www.MyDNS.JP/
// Future Versatile Group    http://www.fvg-on.net/
// 
// ------------------------------------------------------------
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
        if (preg_match($PATTERN, $DATA))
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
// Check ban4ip SQLite3 DB
// ----------------------------------------------------------------------
// SQLite3データベース用のディレクトリを作成(エラー出力を抑制)
if (!empty($BAN4IPD_CONF['db_dir']))
{
    // PDO接続設定が片方でもないときだけでいい
    if (empty($BAN4IPD_CONF['db_count_pdo_dsn']) || empty($BAN4IPD_CONF['db_ban_pdo_dsn']))
    {
        @mkdir($BAN4IPD_CONF['db_dir']);
        // SQLite3データベース用のディレクトリがないなら
        if (!is_dir($BAN4IPD_CONF['db_dir']))
        {
            print $BAN4IPD_CONF['db_dir']." not found!?"."\n";
            // 終わり
            exit -1;
        }
    }
}

// カウントデータベースに接続(無ければ新規に作成)
if (!empty($BAN4IPD_CONF['db_count_pdo_dsn']))
{
    try
    {
        $BAN4IPD_CONF['count_db'] = new PDO($BAN4IPD_CONF['db_count_pdo_dsn']);
    }
    catch(PDOException $e)
    {
        print $BAN4IPD_CONF['db_count_pdo_dsn']." not Connection!?"."\n";
        print $e->getMessage()."\n";
        // 終わり
        exit -1;
    }
}
else
{
    // カウントデータベースに接続(無ければ新規に作成)
    $BAN4IPD_CONF['count_db'] = new PDO('sqlite:' . $BAN4IPD_CONF['db_dir'].'/count.db');
}

// カウントデータベースに接続できなかったら
if ($BAN4IPD_CONF['count_db'] === FALSE)
{
    print "Cannot connect ".$BAN4IPD_CONF['db_dir'].'/count.db'."!?"."\n";
    // 終わり
    exit -1;
}

// テーブルがなかったら作成
$BAN4IPD_CONF['count_db']->exec('CREATE TABLE IF NOT EXISTS count_tbl (address, service, registdate)');

// インデックスを作成する
try
{
    $BAN4IPD_CONF['count_db']->exec('CREATE INDEX address_idx ON count_tbl (address)');
}
catch(PDOException $e)
{
    // インデックス作成の際のエラーは許容する(重複エラーと思われるため)
}

// カウントデータベースのロックタイムアウト時間を少し長くする
$BAN4IPD_CONF['count_db']->setAttribute(PDO::ATTR_TIMEOUT, $BAN4IPD_CONF['db_timeout']);

// BANデータベースに接続(無ければ新規に作成)
if (!empty($BAN4IPD_CONF['db_ban_pdo_dsn']))
{
    try
    {
        $BAN4IPD_CONF['ban_db'] = new PDO($BAN4IPD_CONF['db_ban_pdo_dsn']);
    }
    catch(PDOException $e)
    {
        print $BAN4IPD_CONF['db_ban_pdo_dsn']." not Connection!?"."\n";
        print $e->getMessage()."\n";
        // 終わり
        exit -1;
    }
}
else
{
    $BAN4IPD_CONF['ban_db'] = new PDO('sqlite:' . $BAN4IPD_CONF['db_dir'].'/ban.db');
}

// BANデータベースに接続できなかったら
if ($BAN4IPD_CONF['ban_db'] === FALSE)
{
    print "Cannot connect ".$BAN4IPD_CONF['db_dir'].'/ban.db'."!?"."\n";
    // 終わり
    exit -1;
}

// テーブルがなかったら作成
$BAN4IPD_CONF['ban_db']->exec('CREATE TABLE IF NOT EXISTS ban_tbl (address, service, protcol, port, rule, unbandate)');

// インデックスを作成する
try
{
    $BAN4IPD_CONF['ban_db']->exec('CREATE INDEX unbandate_idx ON ban_tbl (unbandate)');
}
catch(PDOException $e)
{
    // インデックス作成の際のエラーは許容する(重複エラーと思われるため)
}

// カウントデータベースのロックタイムアウト時間を少し長くする
$BAN4IPD_CONF['ban_db']->setAttribute(PDO::ATTR_TIMEOUT, $BAN4IPD_CONF['db_timeout']);

?>
