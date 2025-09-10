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
function ban4ip_unban($TARGET_CONF)
{
    // 対象IPアドレスを/で分割して配列に設定
    $TARGET_ADDRESS = explode("/", $TARGET_CONF['target_address']);
    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
    if (filter_var($TARGET_ADDRESS[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
    {
        $IPTABLES = $TARGET_CONF['ip6tables'];
    }
    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
    else if (filter_var($TARGET_ADDRESS[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
    {
        $IPTABLES = $TARGET_CONF['iptables'];
    }
    // 対象IPアドレスがIPv4でもIPv6でもないなら
    else
    {
        // 対象IPアドレスはBANの対象だけど、アドレスがおかしい旨のメッセージを設定
        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Ban ".$TARGET_CONF['target_address']." (over ".$TARGET_CONF['maxretry']." counts) ";
        $TARGET_CONF['log_msg'] .= 'Illegal address!?'."\n";
        // 2025.09.09 T.Kabu 結局ここを含めて、exec()とquery()をラッピングすることにした
        // 2025.09.09 T.Kabu PDO経由でMySQLやPostgreSQLと接続していると、何らかの理由で勝手に切断されていることがあり、この後のtry/catchで「General error: 2006 MySQL server has gone away」エラーとなることがある
        // 2021.09.07 T.Kabu どうもSQLite3が、DELETEの時にだけ何かのタイミングでデータベースがロックしているという判断でエラーとなる。実際にはDELETE出来ているので再試行も発生しないので、try/catchでスルーするようにした
        // BANデータベースから対象IPアドレス(とポートとルールが合致するもの)を削除
        $TARGET_CONF = ban4ip_db_exec($TARGET_CONF, 'ban_db', "DELETE FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'");
        // 戻る
        return $TARGET_CONF;
    }
    
    // 対象サービスについてBANのルール設定があるなら
    if (isset($TARGET_CONF['target_rule']))
    {
        // 対象サービスについてBANのプロトコルとポートがともに'all'なら
        if ($TARGET_CONF['target_protcol'] == 'all' && $TARGET_CONF['target_port'] == 'all')
        {
            // UNBANする前のコマンド(exec_befor_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4ip_exec($TARGET_CONF, 'exec_befor_unban');
            
            // ban4ipチェインの設定を取得する
            $PROC_P = popen($IPTABLES." -L ban4ip -n", "r");
            $TARGET_PATTERN = '/^'.$TARGET_CONF['target_rule'].' .* '.preg_replace('/\//', '\/', $TARGET_CONF['target_address']).'.*$/';
            // ban4ipチェインに該当ルールがあるなら
            if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
            {
                // ban4ipチェインから対象BANを削除する
                system($IPTABLES.' -D ban4ip --source '.$TARGET_CONF['target_address'].' --jump '.$TARGET_CONF['target_rule']);
                // 対象IPアドレスをUNBANした旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unban ".$TARGET_CONF['target_address']."\n";
            }
            else
            {
                // 対象IPアドレスがUNBANされている旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unbaned already ".$TARGET_CONF['target_address']."\n";
            }
            pclose($PROC_P);
            
            // UNBANした後のコマンド(exec_after_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4ip_exec($TARGET_CONF, 'exec_after_unban');
        }
        // 対象サービスについてBANのプロトコルとポートが個別に設定されているなら
        else if (isset($TARGET_CONF['target_protcol']) && isset($TARGET_CONF['target_port']))
        {
            // -----------------------------
            // BANルールを設定する
            // -----------------------------
            // UNBANする前のコマンド(exec_befor_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4ip_exec($TARGET_CONF, 'exec_befor_unban');
            
            // ban4ipチェインの設定を取得する
            $PROC_P = popen($IPTABLES." -L ban4ip -n", "r");
            $TARGET_PATTERN = '/^'.$TARGET_CONF['target_rule'].' .* '.preg_replace('/\//', '\/', $TARGET_CONF['target_address']).'.* '.$TARGET_CONF['target_protcol'].' dpt:'.$TARGET_CONF['target_port'].'$/';
            // ban4ipチェインに該当ルールがあるなら
            if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
            {
                // ban4ipチェインから対象BANを削除する
                system($IPTABLES.' -D ban4ip --source '.$TARGET_CONF['target_address'].' --proto '.$TARGET_CONF['target_protcol'].' --dport '.$TARGET_CONF['target_port'].' --jump '.$TARGET_CONF['target_rule']);
                // 対象IPアドレスをUNBANした旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unban ".$TARGET_CONF['target_address']."\n";
            }
            else
            {
                // 対象IPアドレスがUNBANされている旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unbaned already ".$TARGET_CONF['target_address']."\n";
            }
            pclose($PROC_P);
            
            // UNBANした後のコマンド(exec_after_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4ip_exec($TARGET_CONF, 'exec_after_unban');
        }
        else
        {
            // 対象IPアドレスをUNBAN?した旨を出力
            $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unban? ".$TARGET_CONF['target_address']."\n";
        }
    }
    // 2025.09.09 T.Kabu 結局ここを含めて、exec()とquery()をラッピングすることにした
    // 2025.09.09 T.Kabu PDO経由でMySQLやPostgreSQLと接続していると、何らかの理由で勝手に切断されていることがあり、この後のtry/catchで「General error: 2006 MySQL server has gone away」エラーとなることがある
    // 2021.09.07 T.Kabu どうもSQLite3が、DELETEの時にだけ何かのタイミングでデータベースがロックしているという判断でエラーとなる。実際にはDELETE出来ているので再試行も発生しないので、try/catchでスルーするようにした
    // BANデータベースから対象IPアドレス(とポートとルールが合致するもの)を削除
    $TARGET_CONF = ban4ip_db_exec($TARGET_CONF, 'ban_db', "DELETE FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'");
    $RESULT = $TARGET_CONF['exec_result'];
    // 削除できなかったら
    if ($RESULT === FALSE)
    {
        // エラーの旨メッセージを設定
        $TARGET_CONF['log_msg'] .= date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: WARN [".$TARGET_CONF['target_service']."] Cannot Query the DB, ".$TARGET_CONF['target_address']." ... DB File DELETE & REBOOT!(3)"."\n";
        // ログに出力する(親プロセスにログを送信する代わりに)
        log_write($TARGET_CONF);
    }
    // 戻る
    return $TARGET_CONF;
}
?>
