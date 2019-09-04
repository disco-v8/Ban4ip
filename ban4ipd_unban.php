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
        // BANデータベースから対象IPアドレス(とポートとルールが合致するもの)を削除
        $TARGET_CONF['ban_db']->exec("DELETE FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'");
        // 戻る
        return $TARGET_CONF;
    }
    
    // 対象サービスについてBANのルール設定があるなら
    if (isset($TARGET_CONF['target_rule']))
    {
        // 対象サービスについてBANのプロトコルとポートがともに'all'なら
        if ($TARGET_CONF['target_protcol'] == 'all' && $TARGET_CONF['target_port'] == 'all')
        {
            // -----------------------------
            // ip6tablesに対象IPアドレスをBANするルールを設定する
            // -----------------------------
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
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unbaned aleady ".$TARGET_CONF['target_address']."\n";
            }
            pclose($PROC_P);
            
            // UNBANした後のコマンド(exec_afer_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4ip_exec($TARGET_CONF, 'exec_after_unban');
        }
        // 対象サービスについてBANのプロトコルとポートが個別に設定されているなら
        else if (isset($TARGET_CONF['target_protcol']) && isset($TARGET_CONF['target_port']))
        {
            // -----------------------------
            // ip6tablesに対象IPアドレスをBANするルールを設定する
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
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unbaned aleady ".$TARGET_CONF['target_address']."\n";
            }
            pclose($PROC_P);
            
            // UNBANした後のコマンド(exec_afer_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4ip_exec($TARGET_CONF, 'exec_after_unban');
        }
        else
        {
            // 対象IPアドレスをUNBAN?した旨を出力
            $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unban? ".$TARGET_CONF['target_address']."\n";
        }
    }
    // BANデータベースから対象IPアドレス(とポートとルールが合致するもの)を削除
    $RESULT = $TARGET_CONF['ban_db']->exec("DELETE FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'");
    // 削除できなかったら
    if ($RESULT === FALSE)
    {
        $TARGET_CONF['delete_err_count'] += 1;
        // もし検出回数以上になったら
        if ($TARGET_CONF['delete_err_count'] >= $TARGET_CONF['maxretry'])
        {
            // 強制ダメージリカバリ
            $TARGET_CONF['damage_recover'] = 1;
            // データベースファイルをリカバリ
            ban4ip_dbcheck($TARGET_CONF);
        }
    }
    // 戻る
    return $TARGET_CONF;
}
?>
