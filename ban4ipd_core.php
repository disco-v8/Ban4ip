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
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4ipd_exec.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_mail_send()
{
    // メール送信のパラメータを設定(それぞれのプロセスのTARGET_CONFがなかったり、宛先がなかったらFALSEで戻る。それ以外は空でも送信処理をする)
    $MAIL_ARG = func_get_args();
    // それぞれのプロセスのTARGET_CONFが設定されていなかったり、配列でなかったら
    if (!isset($MAIL_ARG[0]) || !is_array($MAIL_ARG[0]))
    {
        // FALSEで戻る
        return FALSE;
    }
    // パラメータがあるなら
    else
    {
        // TARGET_CONFを設定
        $TARGET_CONF = $MAIL_ARG[0];
    }
    
    // 宛先に相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[1]))
    {
        // NULLを設定
///        $MAIL_TO = NULL;
        // FALSEで戻る
        return FALSE;
    }
    // パラメータがあるなら
    else
    {
        // 宛先を設定
        $MAIL_TO = $MAIL_ARG[1];
    }
    
    // タイトルに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[2]))
    {
        // NULLを設定
        $MAIL_TITLE = NULL;
    }
    // パラメータがあるなら
    else
    {
        // タイトルを設定
        $MAIL_TITLE = $MAIL_ARG[2];
    }
    
    // 本文に相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[3]))
    {
        // NULLを設定
        $MAIL_STR = NULL;
    }
    // パラメータがあるなら
    else
    {
        // 本文を設定
        $MAIL_STR = $MAIL_ARG[3];
    }
    
    // ヘッダーオプションに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[4]))
    {
        // NULLを設定
        $MAIL_HEADER = NULL;
    }
    // パラメータがあるなら
    else
    {
        // ヘッダーオプションを設定
        $MAIL_HEADER = $MAIL_ARG[4];
    }
    
    // メールオプションに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[5]))
    {
        // NULLを設定
        $MAIL_PARAM = NULL;
    }
    // パラメータがあるなら
    else
    {
        // メールオプションを設定
        $MAIL_PARAM = $MAIL_ARG[5];
    }
    
    // メール送信レートテーブルから、対象メッセージの現在時刻 - 対象時間より昔のデータを削除
    $TARGET_CONF['mailrate_db']->exec("DELETE FROM mailrate_tbl WHERE registdate < (".(time() - $TARGET_CONF['mailratetime']).")");
    // メール送信レートテーブルに対象メッセージを登録
    $RESULT = @$TARGET_CONF['mailrate_db']->exec("INSERT INTO mailrate_tbl VALUES ('".$MAIL_TO."','".$MAIL_TITLE."',".time().")");
    
    // もし新しく登録できたら
    if ($RESULT)
    {
        // メール送信
        $RESULT = mb_send_mail(
                $MAIL_TO,
                $MAIL_TITLE,
                $MAIL_STR,
                $MAIL_HEADER,
                $MAIL_PARAM);
    }
    else
    {
        // メールは送信しない
    }
    // 戻る
    return $RESULT;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_end($signo)
{
    global $BAN4IPD_CONF;
    
    // フォークした子プロセスがあるなら
    if (isset($BAN4IPD_CONF['proclist']) && is_array($BAN4IPD_CONF['proclist']))
    {
        // フォークした子プロセスをkillする
        foreach ($BAN4IPD_CONF['proclist'] as $PID)
        {
            // 子プロセスをkillする
            posix_kill($PID, SIGTERM);
            // 子プロセスの終了を待つ
            pcntl_waitpid($PID, $STATUS, WUNTRACED);
        }
    }
    unset($BAN4IPD_CONF['proclist']);
    
    // シグナル別に処理
    switch ($signo)
    {
        // SIGINTなら
        case SIGINT:
        // SIGTERMなら
        case SIGTERM:
            // ソケットファイルがあれば
            if (is_executable($BAN4IPD_CONF['socket_file']))
            {
                // UNIXソケットを閉じる
                socket_close($BAN4IPD_CONF['socket']);
                // ソケットファイルを削除する
                unlink($BAN4IPD_CONF['socket_file']);
            }
            
            // iptablesからban4ipチェインを削除する
            system($BAN4IPD_CONF['iptables'].' -D INPUT -j ban4ip');
            system($BAN4IPD_CONF['iptables'].' -F ban4ip');
            system($BAN4IPD_CONF['iptables'].' -X ban4ip');
            // ip6tablesからban4ipチェインを削除する
            system($BAN4IPD_CONF['ip6tables'].' -D INPUT -j ban4ip');
            system($BAN4IPD_CONF['ip6tables'].' -F ban4ip');
            system($BAN4IPD_CONF['ip6tables'].' -X ban4ip');
            
            // PIDファイルがあれば
            if (is_file($BAN4IPD_CONF['pid_file']))
            {
                // PIDファイルを削除する
                unlink($BAN4IPD_CONF['pid_file']);
            }
            
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: END"."\n";
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
            // ソケットファイルがあれば
            if (is_executable($BAN4IPD_CONF['socket_file']))
            {
                // UNIXソケットを閉じる
                socket_close($BAN4IPD_CONF['socket']);
                // ソケットファイルを削除する
                unlink($BAN4IPD_CONF['socket_file']);
            }
            
            // 再読み込み要求(=1)を設定
            $BAN4IPD_CONF['reload'] = 1;
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: RELOAD"."\n";
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
            // エラーメッセージに、UNIXソケットを開けない旨を設定
            $ERR_MSG = 'Cannot create socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットとファイルがBINDできなかったら
        if (socket_bind($BAN4IPD_CONF['socket'], $BAN4IPD_CONF['socket_file']) == FALSE)
        {
            // エラーメッセージに、UNIXソケットとファイルがBINDできない旨を設定
            $ERR_MSG = 'Cannot bind socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットをノンブロッキングモードに変更できなかったら
        if (socket_set_nonblock($BAN4IPD_CONF['socket']) == FALSE)
        {
            // エラーメッセージに、UNIXソケットをノンブロッキングモードに変更できない旨を設定
            $ERR_MSG = 'Cannot set non block socket'.'!?';
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
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: START under ".$BAN4IPD_CONF['system_pid0']."\n";
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
            if ($SOCK_RESULT === FALSE)
            {
                // 再読み込み要求(reload=1)ではないなら
                if ($BAN4IPD_CONF['reload'] != 1)
                {
                    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR "."Cannot socket_select!? (".socket_strerror(socket_last_error()).")"."\n";
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                }
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
                // データの受信ができたなら
                if ($SOCK_RESULT != FALSE)
                {
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                }
                // できなかったら
                else
                {
                    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR "."Cannot socket_recvfrom!? (".socket_strerror(socket_last_error()).")"."\n";
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                }
            }
            
            // カウントデータベースから最大カウント時間を過ぎたデータをすべて削除(いわゆる削除漏れのゴミ掃除)
            $BAN4IPD_CONF['count_db']->exec("DELETE FROM count_tbl WHERE registdate < ".$BAN4IPD_CONF['maxfindtime']);
            // BANデータベースでBAN解除対象IPアドレスを取得
            $RESULT = $BAN4IPD_CONF['ban_db']->query("SELECT * FROM ban_tbl WHERE unbandate < ".local_time());
            // BAN解除対象IPアドレスの取得ができなかったら
            if ($RESULT === FALSE)
            {
                $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR "."Cannot query!? (".socket_strerror(socket_last_error()).")"."\n";
                // ログに出力する
                log_write($BAN4IPD_CONF);
            }
            // BAN解除対象IPアドレスの取得ができたら
            else
            {
                // 該当データがあったらUNBANする
                while ($DB_DATA = $RESULT->fetch(PDO::FETCH_ASSOC))
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
                // WAL内のデータをDBに書き出し(こうしないとban4ipc listで確認したり、別プロセスでsqlite3ですぐに確認できない…が、負荷的にはWALにしている意味がないよなぁ…一応banの場合は発行時に、unbanはここですべてが終わった時に書き出し処理をする。count_dbはしない)
///                $BAN4IPD_CONF['count_db']->exec("PRAGMA wal_checkpoint");
                $BAN4IPD_CONF['ban_db']->exec("PRAGMA wal_checkpoint");
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
