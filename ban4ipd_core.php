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
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4ipd_unban.php");
?>
<?php
// --------------------
// Sub Routine
// --------------------
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
function ban4ip_exec($BAN4IPD_CONF, $TARGET_CMD)
{
    // 既存のログメッセージ待避
    $LOG_MSG = $BAN4IPD_CONF['log_msg'];
    
    // 指定されたコマンド(exec_befor/after_ban/unban)が設定されていないなら
    if (!isset($BAN4IPD_CONF[$TARGET_CMD]) || (isset($BAN4IPD_CONF[$TARGET_CMD]) && strlen($BAN4IPD_CONF[$TARGET_CMD]) == 0))
    {
        // コマンド実行処理を抜ける
        return $BAN4IPD_CONF;
    }
    // 指定されたコマンドをスペースで配列に変換
    $EXEC_CMD = preg_split("/[\s\t]+/", $BAN4IPD_CONF[$TARGET_CMD]);
    // 指定されたコマンド(exec_befor/after_ban/unban)が実行できないなら
    if (!is_executable($EXEC_CMD[0]))
    {
        // 指定されたコマンドが実行できない旨のメッセージを設定
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", $BAN4IPD_CONF['logtime'])." ban4ip[".getmypid()."]: WARN [".$BAN4IPD_CONF['target_service']."] Cannot execute ".$TARGET_CMD."!? (".$BAN4IPD_CONF[$TARGET_CMD].")"."\n";
        // 親プロセスに送信
        ban4ip_sendmsg($BAN4IPD_CONF);
        
        // 既存のログメッセージを戻す
        $BAN4IPD_CONF['log_msg'] = $LOG_MSG;
        // コマンド実行処理を抜ける
        return $BAN4IPD_CONF;
    }
    // 指定されたコマンドを実行
    $RESULT = system($BAN4IPD_CONF[$TARGET_CMD]);
    
    // 指定されたコマンドを実行した旨のメッセージを設定
    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", $BAN4IPD_CONF['logtime'])." ban4ip[".getmypid()."]: NOTICE [".$BAN4IPD_CONF['target_service']."] EXEC ".$TARGET_CMD." \"".$BAN4IPD_CONF[$TARGET_CMD]."\"";
    // 実行結果があるなら
    if (strlen($RESULT))
    {
        // 一部を返す
        $BAN4IPD_CONF['log_msg'] .=" (".substr($RESULT, 0, 32).")";
    }
    $BAN4IPD_CONF['log_msg'] .= "\n";
    // 親プロセスに送信
    ban4ip_sendmsg($BAN4IPD_CONF);
    
    // 既存のログメッセージを戻す
    $BAN4IPD_CONF['log_msg'] = $LOG_MSG;
    // コマンド実行処理を抜ける
    return $BAN4IPD_CONF;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_end($signo)
{
    global $BAN4IPD_CONF;
    
    // フォークした子プロセスをkillする
    foreach ($BAN4IPD_CONF['proclist'] as $PID)
    {
        // 子プロセスをkillする
        posix_kill($PID, SIGTERM);
        // 子プロセスの終了を待つ
        pcntl_waitpid($PID, $STATUS, WUNTRACED);
    }
    unset($BAN4IPD_CONF['proclist']);
    
    // シグナル別に処理
    switch ($signo)
    {
        // SIGINTなら
        case SIGINT:
        // SIGTERMなら
        case SIGTERM:
            // UNIXソケットを閉じる
            socket_close($BAN4IPD_CONF['socket']);
            // ソケットファイルを削除する
            unlink($BAN4IPD_CONF['socket_file']);
            
            // iptablesからban4ipチェインを削除する
            system($BAN4IPD_CONF['iptables'].' -D INPUT -j ban4ip');
            system($BAN4IPD_CONF['iptables'].' -F ban4ip');
            system($BAN4IPD_CONF['iptables'].' -X ban4ip');
            // ip6tablesからban4ipチェインを削除する
            system($BAN4IPD_CONF['ip6tables'].' -D INPUT -j ban4ip');
            system($BAN4IPD_CONF['ip6tables'].' -F ban4ip');
            system($BAN4IPD_CONF['ip6tables'].' -X ban4ip');
            
            // PIDファイルを削除する
            unlink($BAN4IPD_CONF['pid_file']);
            
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s")." ban4ip[".getmypid()."]: END"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // ログファイルポインタが開かれているなら
            if (isset($BAN4IPD_CONF['log_p']))
            {
                // ログファイルを閉じる
                fclose($BAN4IPD_CONF['log_p']);
            }
            // 終わり
            exit;
            break;
        // SIGHUPなら
        case SIGHUP:
            // UNIXソケットを閉じる
            socket_close($BAN4IPD_CONF['socket']);
            // ソケットファイルを削除する
            unlink($BAN4IPD_CONF['socket_file']);
            
            // 再読み込み要求(=1)を設定
            $BAN4IPD_CONF['reload'] = 1;
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s")." ban4ip[".getmypid()."]: RELOAD"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // ログファイルポインタが開かれているなら
            if (isset($BAN4IPD_CONF['log_p']))
            {
                // ログファイルを閉じる
                fclose($BAN4IPD_CONF['log_p']);
            }
            break;
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Check Other process
// ----------------------------------------------------------------------
// PIDファイルがあるなら
if (is_file($BAN4IPD_CONF['pid_file']))
{
    // エラーメッセージに、別のプロセスがある旨を設定
    $ERR_MSG = 'Found other process : '.$BAN4IPD_CONF['pid_file'].'!?';
    // メッセージを表示
    print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
    // 終わり
    exit -1;
}
// ないなら
else
{
    // ログファイルの指定があるなら
    if (isset($BAN4IPD_CONF['log_file']))
    {
        // ファイルをtouch(無ければ新規作成)
        touch($BAN4IPD_CONF['log_file']);
        // ファイルのパーミッションを700に設定
        chmod($BAN4IPD_CONF['log_file'], 0600);
    }
    // PIDファイルを新規に開く
    $PID_FILE = fopen($BAN4IPD_CONF['pid_file'], "a");
    // PIDファイルにプロセスIDを出力(改行しない)
    fputs($PID_FILE, getmypid());
    // PIDファイルを閉じる
    fclose($PID_FILE);
}
?>
<?php
// ----------------------------------------------------------------------
// Check iptanles/ip6tables
// ----------------------------------------------------------------------
// iptables
if (!is_executable($BAN4IPD_CONF['iptables']))
{
    fprintf(STDERR, "Cannot execute iptables!?\n");
    exit -1;
}

// ip6tables
if (!is_executable($BAN4IPD_CONF['ip6tables']))
{
    fprintf(STDERR, "Cannot execute ip6tables!?\n");
    exit -1;
}

// -----------------------------
// iptablesからban4ip関連チェインを削除する
// -----------------------------
// INPUTチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['iptables']." -L INPUT -n", "r");
$TARGET_PATTERN = '/^ban4ip[\s]{1,}all /';
// INPUTチェインにban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['iptables'].' -D INPUT -j ban4ip > /dev/null');
}
pclose($PROC_P);

// ban4ipチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['iptables']." -L -n", "r");
$TARGET_PATTERN = '/^Chain[\s]{1,}ban4ip /';
// ban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['iptables'].' -F ban4ip > /dev/null');
    system($BAN4IPD_CONF['iptables'].' -X ban4ip > /dev/null');
}
pclose($PROC_P);

// -----------------------------
// ip6tablesからban4ip関連チェインを削除する
// -----------------------------
// INPUTチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['ip6tables']." -L INPUT -n", "r");
$TARGET_PATTERN = '/^ban4ip[\s]{1,}all /';
// INPUTチェインにban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['ip6tables'].' -D INPUT -j ban4ip > /dev/null');
}
pclose($PROC_P);

// ban4ipチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['ip6tables']." -L -n", "r");
$TARGET_PATTERN = '/^Chain[\s]{1,}ban4ip /';
// ban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['ip6tables'].' -F ban4ip > /dev/null');
    system($BAN4IPD_CONF['ip6tables'].' -X ban4ip > /dev/null');
}
pclose($PROC_P);

// iptablesにban4ipチェインを新設する
system($BAN4IPD_CONF['iptables'].' -N ban4ip');
system($BAN4IPD_CONF['iptables'].' -A ban4ip -j RETURN');
// ip6tablesにban4ipチェインを新設する
system($BAN4IPD_CONF['ip6tables'].' -N ban4ip');
system($BAN4IPD_CONF['ip6tables'].' -A ban4ip -j RETURN');

// iptablesのINPUTチェインにban4ipチェインを追加する(最初に)
system($BAN4IPD_CONF['iptables'].' -I INPUT -j ban4ip');
// ip6tablesのINPUTチェインにban4ipチェインを追加する(最初に)
system($BAN4IPD_CONF['ip6tables'].' -I INPUT -j ban4ip');
?>
<?php
// ----------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------
do // SIGHUPに対応したループ構造にしている
{
    // 再読み込み要求を初期化
    $BAN4IPD_CONF['reload'] = 0;
    
    // サブ設定ディレクトリの設定があるなら
    if (isset($BAN4IPD_CONF['conf_dir']) && is_dir($BAN4IPD_CONF['conf_dir']))
    {
        // サブ設定ディレクトリを開く
        $CONF_DIR = opendir($BAN4IPD_CONF['conf_dir']);
        // サブ設定ディレクトリからファイルの一覧を取得
        while (($CONF_FILE = readdir($CONF_DIR)) !== false)
        {
            $BAN4IPD_CONF['conf_file'] = $BAN4IPD_CONF['conf_dir'].'/'.$CONF_FILE;
            // サブ設定ファイルなら
            if (is_file($BAN4IPD_CONF['conf_file']) && preg_match('/.conf$/', $BAN4IPD_CONF['conf_file']))
            {
                // プロセスをフォーク
                $PID = pcntl_fork();
                
                // フォークできなかったら
                if ($PID == -1)
                {
                    // エラーメッセージに、プロセスをフォークできない旨を設定
                    $ERR_MSG = 'Cannot fork process'.'!?';
                    // メッセージを表示
                    print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
                    // 終わり
                    exit -1;
                }
                // フォークできたら
                else if ($PID != 0)
                {
                    // 親プロセスの場合
                    $BAN4IPD_CONF['proclist'][] = $PID;
                }
                // 子プロセスなら
                else // if ($PID == 0)
                {
                    // 子プロセス用のサブルーチンファイルを読み込み
                    require(__DIR__.'/ban4ipd_sub.php');
                    // サブ設定ファイルを読み込んで変数展開する
                    $TARGET_CONF = array_merge($BAN4IPD_CONF, parse_ini_file($BAN4IPD_CONF['conf_file'], FALSE, INI_SCANNER_NORMAL));
                    // 実際の処理を開始
                    ban4ip_start($TARGET_CONF);
                    // ここで終わり(子プロセスなので)
                    exit;
                }
            }
        }
        closedir($CONF_DIR);
        
        // シグナルハンドラを設定します(親プロセスだけ)
        declare(ticks = 1);
        pcntl_signal(SIGINT,  "ban4ip_end");
        pcntl_signal(SIGTERM, "ban4ip_end");
        pcntl_signal(SIGHUP,  "ban4ip_end");
        
        
        
        // 親プロセスとしてUNIXソケットを開く
        $BAN4IPD_CONF['socket'] = socket_create(AF_UNIX, SOCK_DGRAM, 0);
        // UNIXソケットが開けなかったら
        if ($BAN4IPD_CONF['socket'] == FALSE )
        {
            // エラーメッセージに、プロセスをフォークできない旨を設定
            $ERR_MSG = 'Cannot create socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットとファイルがBINDできなかったら
        if (socket_bind($BAN4IPD_CONF['socket'], $BAN4IPD_CONF['socket_file']) == FALSE)
        {
            // エラーメッセージに、プロセスをフォークできない旨を設定
            $ERR_MSG = 'Cannot bind socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットをノンブロッキングモードに変更できなかったら
        if (socket_set_block($BAN4IPD_CONF['socket']) == FALSE)
        {
            // エラーメッセージに、プロセスをフォークできない旨を設定
            $ERR_MSG = 'Cannot set block socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットを配列に設定(読み込みできるかどうかだけ調べられればいいのでREAD_ARRAYに設定)
        $SOCK_READ_ARRAY = array($BAN4IPD_CONF['socket']);
        $SOCK_WRITE_ARRAY  = NULL;
        $SOCK_EXCEPT_ARRAY = NULL;
        
        // 親プロセスの開始完了を出力
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s")." ban4ip[".getmypid()."]: START"."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        
        // 再読み込み要求(=1)が来るまで無限ループ(親プロセスがSIGHUPを受けると1)
        while($BAN4IPD_CONF['reload'] == 0)
        {
            // 終わってしまった子プロセスのステータスを取得
            pcntl_wait($STATUS, WNOHANG);
            
            // UNIXソケットに変化が発生しているか(読み込みができるようになっているか)を取得、$BAN4IPD_CONF['unbantime']だけ待つ
            // (socket_selectによって変数が上書きされるので常に設定)
            $READ_ARRAY = $SOCK_READ_ARRAY;
            $WRITE_ARRAY = $SOCK_WRITE_ARRAY;
            $EXCEPT_ARRAY = $SOCK_EXCEPT_ARRAY;
            $SOCK_RESULT = @socket_select($READ_ARRAY, $WRITE_ARRAY, $EXCEPT_ARRAY, $BAN4IPD_CONF['unbantime']);
            // UNIXソケットの変化が取得できないなら
            if ($SOCK_RESULT === false)
            {
            }
            // UNIXソケットに変化がないなら
            else if ($SOCK_RESULT == 0)
            {
            }
            // 変化があるなら
            else if ($SOCK_RESULT > 0)
            {
                // ソケットからデータを受信して、ログメッセージに設定
                $SOCK_RESULT = socket_recvfrom($BAN4IPD_CONF['socket'], $BAN4IPD_CONF['log_msg'], 255, 0, $SOCK_FROM);
                // ログに出力する
                log_write($BAN4IPD_CONF);
            }
            
            // カウントデータベースから最大カウント時間を過ぎたデータをすべて削除(いわゆる削除漏れのゴミ掃除)
            $BAN4IPD_CONF['count_db']->exec("DELETE FROM count_tbl WHERE registdate < ".$BAN4IPD_CONF['maxfindtime']);
            // BANデータベースでBAN解除対象IPアドレスを取得
            $RESULT = $BAN4IPD_CONF['ban_db']->query("SELECT * FROM ban_tbl WHERE unbandate < ".time());
            // 該当データがあったらUNBANする
            while ($DB_DATA = $RESULT->fetchArray(SQLITE3_ASSOC))
            {
                // UNBANする
                $BAN4IPD_CONF['target_address'] = $DB_DATA['address'];
                $BAN4IPD_CONF['target_service'] = $DB_DATA['service'];
                $BAN4IPD_CONF['target_protcol'] = $DB_DATA['protcol'];
                $BAN4IPD_CONF['target_port'] = $DB_DATA['port'];
                $BAN4IPD_CONF['target_rule'] = $DB_DATA['rule'];
                $BAN4IPD_CONF = ban4ip_unban($BAN4IPD_CONF);
                // ログに出力する
                log_write($BAN4IPD_CONF);
            }
        }
        
        // シグナルハンドラをデフォルトに戻します(親プロセスだけ)
        pcntl_signal(SIGHUP,  SIG_DFL);
        pcntl_signal(SIGTERM, SIG_DFL);
        pcntl_signal(SIGINT,  SIG_DFL);
        
        unset($BAN4IPD_CONF['proclist']);
    }
} while(1);
?>
