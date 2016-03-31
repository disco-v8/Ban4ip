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
function ban4ip_sendmsg($TARGET_CONF)
{
    $FROM_SOCKET = '';
    
    // UNIXソケット経由でメッセージを親プロセスに送信
    $SOCK_RESULT = socket_send($TARGET_CONF['socket'], $TARGET_CONF['log_msg'], strlen($TARGET_CONF['log_msg']), 0);
    // もし送信できなかったら
    if ($SOCK_RESULT === FALSE)
    {
        // エラーメッセージに、親プロセスに送信できなかった旨を設定
        print date("Y-m-d H:i:s")." ban4ip[".getmypid()."]: WARN [".$TARGET_CONF['target_service']."] Cannot send msg by socket!? (".$TARGET_CONF['conf_file'].")"."\n";
        // 終わり
        exit;
    }
    // もしすべてを送信できなかったら
    else if ($SOCK_RESULT != strlen($TARGET_CONF['log_msg']))
    {
        // エラーメッセージに、親プロセスに全てを送信できなかった旨を設定
        print date("Y-m-d H:i:s")." ban4ip[".getmypid()."]: WARN [".$TARGET_CONF['target_service']."] Cannot send full msg by socket!? (".$TARGET_CONF['conf_file'].")"."\n";
        // 終わり
        exit;
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_mailsend($TARGET_CONF)
{
    // メールタイトル初期化
    $MAIL_TITLE = $TARGET_CONF['mail_title']." [".$TARGET_CONF['target_service']."] Ban ".$TARGET_CONF['target_address'];
    // ホスト名が設定されているなら
    if (isset($_SERVER["HOSTNAME"]))
    {
        $MAIL_TITLE .= " from ".$_SERVER["HOSTNAME"];
    }
    // メール本文初期化
    $MAIL_STR = "\n";
    $MAIL_STR .= "Service : ".$TARGET_CONF['target_service']."\n";
    $MAIL_STR .= "IP addr : ".$TARGET_CONF['target_address']."\n";
    // ホスト名の逆引きがONになっていたら
    if ($TARGET_CONF['hostname_lookup'] == 1)
    {
        $MAIL_STR .= "Hostname: ".$TARGET_CONF['target_hostname']."\n";
    }
    $MAIL_STR .= "Protcol : ".$TARGET_CONF['target_protcol']."\n";
    $MAIL_STR .= "Port    : ".$TARGET_CONF['target_port']."\n";
    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
    if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
    {
        $IPTABLES = $TARGET_CONF['ip6tables'];
    }
    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
    else if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
    {
        $IPTABLES = $TARGET_CONF['iptables'];
    }
    // 対象サービスについてBANのルール設定があるなら
    if (isset($TARGET_CONF['target_rule']))
    {
        $MAIL_STR .= "Rule    : ".$TARGET_CONF['target_rule']."\n";
        $MAIL_STR .= "Until   : ".date("Y/m/d H:i:s", $TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])."\n";
        $MAIL_STR .= "\n";
        $MAIL_STR .= "If you want to Unban by manual...\n";
        $MAIL_STR .= "\n";
        // ban4ipチェインから対象IPアドレスについて削除する
        $MAIL_STR .= 'ban4ipc --unban --address '.$TARGET_CONF['target_address'].' --protcol '.$TARGET_CONF['target_protcol'].' --port '.$TARGET_CONF['target_port'].' --rule '.$TARGET_CONF['target_rule']."\n";
        $MAIL_STR .= "\n";
        $MAIL_STR .= "or\n";
        $MAIL_STR .= "\n";
        // 対象サービスについてBANのプロトコルとポートがともに'all'なら
        if ($TARGET_CONF['target_protcol'] == 'all' && $TARGET_CONF['target_port'] == 'all')
        {
            // ip6tablesのban4ipチェインに対象IPアドレスについて追加する
            $MAIL_STR .= $IPTABLES.' -D ban4ip --source '.$TARGET_CONF['target_address'].' --jump '.$TARGET_CONF['target_rule']."\n";
        }
        // 対象サービスについてBANのプロトコルとポートが個別に設定されているなら
        else if (isset($TARGET_CONF['target_protcol']) && isset($TARGET_CONF['target_port']))
        {
            // ip6tablesのban4ipチェインに対象IPアドレスについて追加する
            $MAIL_STR .= $IPTABLES.' -D ban4ip --source '.$TARGET_CONF['target_address'].' --proto '.$TARGET_CONF['target_protcol'].' --dport '.$TARGET_CONF['target_port'].' --jump '.$TARGET_CONF['target_rule']."\n";
        }
    }
    
    foreach($TARGET_CONF['mail_to'] as $MAIL_TO)
    {
        $RESULT = mb_send_mail(
            $MAIL_TO,
            $MAIL_TITLE,
            $MAIL_STR,
            'From: '.$TARGET_CONF['mail_from']."\n".
            $TARGET_CONF['mail_priority']."\n");
    }
    return $RESULT;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_ban($TARGET_CONF)
{
    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
    if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
    {
        $IPTABLES = $TARGET_CONF['ip6tables'];
    }
    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
    else if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
    {
        $IPTABLES = $TARGET_CONF['iptables'];
    }
    // 対象IPアドレスがIPv4でもIPv6でもないなら
    else
    {
        // 対象IPアドレスはBANの対象だけど、アドレスがおかしい旨のメッセージを設定
        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Ban ".$TARGET_CONF['target_address']." (over ".$TARGET_CONF['maxretry']." counts) ";
        $TARGET_CONF['log_msg'] .= 'Illegal address!?'."\n";
        // 戻る
        return $TARGET_CONF;
    }
    $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4ip[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Ban ".$TARGET_CONF['target_address']." (over ".$TARGET_CONF['maxretry']." counts) ";
    
    // 対象サービスについてBANのルール設定があるなら
    if (isset($TARGET_CONF['target_rule']))
    {
        // 対象サービスについてBANのプロトコルとポートがともに'all'なら
        if ($TARGET_CONF['target_protcol'] == 'all' && $TARGET_CONF['target_port'] == 'all')
        {
            // -----------------------------
            // 対象IPアドレスをBANするルールを設定する
            // -----------------------------
            // ban4ipチェインの設定を取得する
            $PROC_P = popen($IPTABLES." -L ban4ip -n", "r");
            $TARGET_PATTERN = '/^'.$TARGET_CONF['target_rule'].' .* '.$TARGET_CONF['target_address'].'.* $/';
            // ban4ipチェインに対象IPアドレスがないなら
            if (psearch($PROC_P, $TARGET_PATTERN) == FALSE)
            {
                $TARGET_CONF['log_msg'] .= 'until '.date("Y/m/d H:i:s", $TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])."\n";
                // ip6tablesのban4ipチェインに対象IPアドレスについて追加する
                system($IPTABLES.' -I ban4ip --source '.$TARGET_CONF['target_address'].' --jump '.$TARGET_CONF['target_rule']);
                // BANした旨をメールで通知
                ban4ip_mailsend($TARGET_CONF);
            }
            else
            {
                $TARGET_CONF['log_msg'] .= 'changed '.date("Y/m/d H:i:s", $TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])."\n";
            }
            pclose($PROC_P);
            // -----------------------------
            // BANデータベースに対象IPアドレス(とポートとルール)を登録(同じ設定がすでにあればUnbanまでの時間を延長、無ければ新規に追加)
            // -----------------------------
            $SQL_STR = "";
            $SQL_STR .= "UPDATE ban_tbl SET service = '".$TARGET_CONF['target_service']."', unbandate = ".($TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])." ";
            $SQL_STR .= "  WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'; ";
            $SQL_STR .= "INSERT INTO ban_tbl (address, service, protcol, port, rule, unbandate) ";
            $SQL_STR .= "  SELECT '".$TARGET_CONF['target_address']."','".$TARGET_CONF['target_service']."','".$TARGET_CONF['target_protcol']."','".$TARGET_CONF['target_port']."','".$TARGET_CONF['target_rule']."',".($TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])." ";
            $SQL_STR .= "    WHERE NOT EXISTS (SELECT 1 FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."') ;";
            $TARGET_CONF['ban_db']->exec($SQL_STR);
        }
        // 対象サービスについてBANのプロトコルとポートが個別に設定されているなら
        else if (isset($TARGET_CONF['target_protcol']) && isset($TARGET_CONF['target_port']))
        {
            // -----------------------------
            // 対象IPアドレスをBANするルールを設定する
            // -----------------------------
            // ban4ipチェインの設定を取得する
            $PROC_P = popen($IPTABLES." -L ban4ip -n", "r");
            $TARGET_PATTERN = '/^'.$TARGET_CONF['target_rule'].' .* '.$TARGET_CONF['target_address'].'.* '.$TARGET_CONF['target_protcol'].' dpt:'.$TARGET_CONF['target_port'].' $/';
            // ban4ipチェインに対象IPアドレスがないなら
            if (psearch($PROC_P, $TARGET_PATTERN) == FALSE)
            {
                $TARGET_CONF['log_msg'] .= 'until '.date("Y/m/d H:i:s", $TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])."\n";
                // ip6tablesのban4ipチェインに対象IPアドレスについて追加する
                system($IPTABLES.' -I ban4ip --source '.$TARGET_CONF['target_address'].' --proto '.$TARGET_CONF['target_protcol'].' --dport '.$TARGET_CONF['target_port'].' --jump '.$TARGET_CONF['target_rule']);
                // BANした旨をメールで通知
                ban4ip_mailsend($TARGET_CONF);
            }
            else
            {
                $TARGET_CONF['log_msg'] .= 'changed '.date("Y/m/d H:i:s", $TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])."\n";
            }
            pclose($PROC_P);
            // -----------------------------
            // BANデータベースに対象IPアドレス(とポートとルール)を登録(同じ設定がすでにあればUnbanまでの時間を延長、無ければ新規に追加)
            // -----------------------------
            $SQL_STR = "";
            $SQL_STR .= "UPDATE ban_tbl SET service = '".$TARGET_CONF['target_service']."', unbandate = ".($TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])." ";
            $SQL_STR .= "  WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'; ";
            $SQL_STR .= "INSERT INTO ban_tbl (address, service, protcol, port, rule, unbandate) ";
            $SQL_STR .= "  SELECT '".$TARGET_CONF['target_address']."','".$TARGET_CONF['target_service']."','".$TARGET_CONF['target_protcol']."','".$TARGET_CONF['target_port']."','".$TARGET_CONF['target_rule']."',".($TARGET_CONF['logtime'] + $TARGET_CONF['bantime'])." ";
            $SQL_STR .= "    WHERE NOT EXISTS (SELECT 1 FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."') ;";
            $TARGET_CONF['ban_db']->exec($SQL_STR);
        }
        // ないなら(対象IPアドレスがBANの対象である旨のみ出力)
        else
        {
            $TARGET_CONF['log_msg'] .= 'not BAN??'."\n";
        }
    }
    // 戻る
    return $TARGET_CONF;
}
?>
