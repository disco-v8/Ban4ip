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
function ban4ip_exec($BAN4IPD_CONF, $TARGET_CMD)
{
    // 既存のログメッセージがあるなら
    if (isset($BAN4IPD_CONF['log_msg']))
    {
        // 既存のログメッセージ待避
        $LOG_MSG = $BAN4IPD_CONF['log_msg'];
    }
    // ないなら
    else
    {
        $LOG_MSG = '';
    }
    
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
///    $RESULT = system($BAN4IPD_CONF[$TARGET_CMD]);
    $RESULT = system($BAN4IPD_CONF[$TARGET_CMD].' --source '.$TARGET_CONF['target_address'].' --proto '.$TARGET_CONF['target_protcol'].' --dport '.$TARGET_CONF['target_port'].' --jump '.$TARGET_CONF['target_rule']);
    
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
