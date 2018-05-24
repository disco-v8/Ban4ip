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
require(__DIR__."/ban4ipd_ban.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function get_networkaddr($IP_ADDR, $IP_MASK)
{
    // 対象IPアドレスをバイナリ形式に変換
    $ADDR['pack'] = inet_pton($IP_ADDR);
    // バイナリ形式に変換できなかったら
    if ($ADDR['pack'] == FALSE)
    {
        // 戻る
        return FALSE;
    }
    
    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
    if (filter_var($IP_ADDR, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
    {
        // IPv6なのに、マスク値が0～128でなかったら
        if ($IP_MASK < 0 || $IP_MASK > 128)
        {
            // 戻る
            return FALSE;
        }
        $ADDR['ip_mask'] = $IP_MASK;
        $ADDR['unpack'] = unpack("n8", $ADDR['pack']);
        // ビットマスクする単位(IPv4=8, IPv6=16)
        $ADDR['pack_len'] = 16;
        // ビットマスク長(IPv4=32, IPv6=128)
        $ADDR['mask_len'] = 128;
        // セパレータ(IPv4=., IPv6=:)
        $ADDR['separator'] = ':';
    }
    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
    else if (filter_var($IP_ADDR, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
    {
        // IPv6なのに、マスク値が0～32でなかったら
        if ($IP_MASK < 0 || $IP_MASK > 32)
        {
            // 戻る
            return FALSE;
        }
        $ADDR['ip_mask'] = $IP_MASK;
        $ADDR['unpack'] = unpack("C4", $ADDR['pack']);
        // ビットマスクする単位(IPv4=8, IPv6=16)
        $ADDR['pack_len'] = 8;
        // ビットマスク長(IPv4=32, IPv6=128)
        $ADDR['mask_len'] = 32;
        // セパレータ(IPv4=., IPv6=:)
        $ADDR['separator'] = '.';
    }
    else
    {
        // 戻る
        return FALSE;
    }
    
    // マスク対象カウント初期化
    $pack_num = 1;
    // マスクの残ビットにビットマスク長を設定、残ビットが0よりあるならループ継続、継続する場合には残ビットからマスク単位を引く
    for ($MASK = $ADDR['mask_len']; $MASK > 0; $MASK -= $ADDR['pack_len'])
    {
        // 残ビットがマスク単位より大きいなら
        if ($ADDR['ip_mask'] > $ADDR['pack_len'])
        {
            // マスク
            $ADDR['unpack'][$pack_num] &= (pow(2, $ADDR['pack_len']) - 1);
            // 残ビットからマスク単位を引く
            $ADDR['ip_mask'] -= $ADDR['pack_len'];
        }
        // 残ビットがマスク単位と同じか小さいなら
        else
        {
            // マスク
            $ADDR['unpack'][$pack_num] &= ((pow(2, $ADDR['pack_len']) -1) ^ (pow(2, $ADDR['pack_len'] - $ADDR['ip_mask']) -1));
            // 残ビットを0にする
            $ADDR['ip_mask'] = 0;
        }
        // マスク対象カウント加算
        $pack_num ++;
    }
    
    $NETWORK_ADDR = "";
    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
    if (filter_var($IP_ADDR, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
    {
        foreach ($ADDR['unpack'] as $IP_D)
        {
            $NETWORK_ADDR .= dechex($IP_D).$ADDR['separator'];
        }
    }
    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
    else if (filter_var($IP_ADDR, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
    {
        foreach ($ADDR['unpack'] as $IP_D)
        {
            $NETWORK_ADDR .= $IP_D.$ADDR['separator'];
        }
    }
    // 最後のseparatorを取り除く
    $NETWORK_ADDR = rtrim($NETWORK_ADDR, $ADDR['separator']);
    // 対象IPアドレスを省略形にして、ネットマスクをつける(ip6tables対策)
    $NETWORK_ADDR = inet_ntop(inet_pton($NETWORK_ADDR)).'/'.$IP_MASK;
    
    // ネットワークアドレスを返して戻る
    return $NETWORK_ADDR;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function check_safeaddr($TARGET_CONF)
{
    // ホワイトリスト設定がないなら
    if (!isset($TARGET_CONF['safe_address']) || !is_array($TARGET_CONF['safe_address']))
    {
        // 戻る(対象IPアドレスはホワイトリストに含まれていない)
        return FALSE;
    }
    
    // 対象IPアドレスがホワイトリストの中にあるかどうか確認
    foreach ($TARGET_CONF['safe_address'] as $SAFE_ADDRESS)
    {
        // 対象アドレスを設定
        $TARGET_ADDRESS = $TARGET_CONF['target_address'];
        // ホワイトIPアドレスを/で分割して配列に設定
        $SAFE_ADDRESS = explode("/", $SAFE_ADDRESS);
        // 対象IPアドレスもホワイトIPアドレスもIPv6なら(IPv6だったら文字列そのものが返ってくる)
        if ((filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE) &&
            (filter_var($SAFE_ADDRESS[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE))
        {
            // ホワイトIPアドレスがネットワークアドレス指定なら、
            if (isset($SAFE_ADDRESS[1]) && ($SAFE_ADDRESS[1] >= 0 && $SAFE_ADDRESS[1] < 128))
            {
                // 対象IPアドレスとホワイトIPアドレスのネットワークアドレスを取得
                $TARGET_ADDRESS = get_networkaddr($TARGET_CONF['target_address'], $SAFE_ADDRESS[1]);
                $SAFE_ADDRESS = get_networkaddr($SAFE_ADDRESS[0], $SAFE_ADDRESS[1]);
            }
            // でなければ、そのまま比較対象とする
            else
            {
                $SAFE_ADDRESS = $SAFE_ADDRESS[0];
            }
        }
        // 対象IPアドレスもホワイトIPアドレスもIPv4なら(IPv4だったら文字列そのものが返ってくる)
        else if ((filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE) &&
                 (filter_var($SAFE_ADDRESS[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE))
        {
            // ホワイトIPアドレスがネットワークアドレス指定なら、
            if (isset($SAFE_ADDRESS[1]) && ($SAFE_ADDRESS[1] >= 0 && $SAFE_ADDRESS[1] < 32))
            {
                // 対象IPアドレスとホワイトIPアドレスのネットワークアドレスを取得
                $TARGET_ADDRESS = get_networkaddr($TARGET_CONF['target_address'], $SAFE_ADDRESS[1]);
                $SAFE_ADDRESS = get_networkaddr($SAFE_ADDRESS[0], $SAFE_ADDRESS[1]);
            }
            // でなければ、そのまま比較対象とする
            else
            {
                $SAFE_ADDRESS = $SAFE_ADDRESS[0];
            }
        }
        // 対象IPアドレスとホワイトIPアドレスが等しいなら
        if ($TARGET_ADDRESS === $SAFE_ADDRESS)
        {
            // 戻る(対象IPアドレスはホワイトリストに含まれている)
            return TRUE;
        }
    }
    // 戻る(対象IPアドレスはホワイトリストに含まれていない)
    return FALSE;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function check_safekeyword($TARGET_CONF)
{
    // ホワイトリスト設定がないなら
    if (!isset($TARGET_CONF['safe_keyword']) || !is_array($TARGET_CONF['safe_keyword']))
    {
        // 戻る(対象キーワードはホワイトリストに含まれていない)
        return FALSE;
    }
    
    // 対象キーワードがホワイトリストの中にあるかどうか確認
    foreach ($TARGET_CONF['safe_keyword'] as $SAFE_ADDRESS)
    {
        // 対象キーワードを設定
        $TARGET_ADDRESS = $TARGET_CONF['target_keyword'];
        
        // 対象キーワードとホワイトキーワードが等しいなら
        if ($TARGET_ADDRESS === $SAFE_ADDRESS)
        {
            // 戻る(対象キーワードはホワイトリストに含まれている)
            return TRUE;
        }
    }
    // 戻る(対象キーワードはホワイトリストに含まれていない)
    return FALSE;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_close($TARGET_CONF)
{
    // UNIXソケットが開いていたら
    if (isset($TARGET_CONF['socket']) && is_resource($TARGET_CONF['socket']))
    {
        // UNIXソケットを切断
        socket_close($TARGET_CONF['socket']);
    }
    
    // inotifyによる監視をしていたら
    if (isset($TARGET_CONF['target_inotify']) && is_resource($TARGET_CONF['target_inotify']))
    {
        // inotifyによる監視を削除
        inotify_rm_watch($TARGET_CONF['target_inotify'], $TARGET_CONF['target_watch']);
        fclose($TARGET_CONF['target_inotify']);
    }
    
    // 対象ファイルが開いていたら
    if (isset($TARGET_CONF['target_fp']) && is_resource($TARGET_CONF['target_fp']))
    {
        // 対象ファイルを閉じる
        fclose($TARGET_CONF['target_fp']);
    }
    
    // パラメータを戻す
    return $TARGET_CONF;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_sendmsg($TARGET_CONF)
{
    $FROM_SOCKET = '';
    $SEND_MSG = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ".$TARGET_CONF['log_msg'];
    
    // UNIXソケットが開いていなかったら
    if (!isset($TARGET_CONF['socket']) || !is_resource($TARGET_CONF['socket']))
    {
        // エラーメッセージに、UNIXソケットが開いていない旨を設定
        print date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: WARN [".$TARGET_CONF['target_service']."] Socket not open!? (".$TARGET_CONF['conf_file'].")"."\n";
        // 戻る
        return;
    }
    // UNIXソケット経由でメッセージを親プロセスに送信
    $SOCK_RESULT = socket_send($TARGET_CONF['socket'], $SEND_MSG, strlen($SEND_MSG), 0);
    // もし送信できなかったら
    if ($SOCK_RESULT === FALSE)
    {
        // エラーメッセージに、親プロセスに送信できなかった旨を設定
        print date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: WARN [".$TARGET_CONF['target_service']."] Cannot send msg by socket!? (".$TARGET_CONF['conf_file'].")"."\n";
        // 戻る
        return;
    }
    // もしすべてを送信できなかったら
    else if ($SOCK_RESULT != strlen($SEND_MSG))
    {
        // エラーメッセージに、親プロセスに全てを送信できなかった旨を設定
        print date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: WARN [".$TARGET_CONF['target_service']."] Cannot send full msg by socket!? (".$TARGET_CONF['conf_file'].")"."\n";
        // 戻る
        return;
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_dbcheck($TARGET_CONF)
{
    // ダメージリカバリが1:ONなら
    if (isset($TARGET_CONF['damage_recover']) && $TARGET_CONF['damage_recover'] == 1)
    {
        // エラーの旨メッセージを設定
        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4ip[".getmypid()."]: INFO [".$TARGET_CONF['target_service']."] Found(2)".$TARGET_CONF['target_address']." (RESULT_COUNT ERROR!? DELETE & REBOOT!)"."\n";
        // 親プロセスに送信
        ban4ip_sendmsg($TARGET_CONF);
        // カウント用データベースファイルを削除
        unlink($TARGET_CONF['db_dir'].'/count.db');
        // サービスを再起動する
        system('/usr/bin/ban4ipc restart');
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_loop($TARGET_CONF)
{
    // ログデータ初期化
    $LOGDATA = '';
    
    // イベントの有無が読める限り
    while (($EVENTS = inotify_read($TARGET_CONF['target_inotify'])) !== false)
    {
        // イベント発生
        foreach($EVENTS as $EVENT)
        {
            // ファイルが新しくなったなら
            if ($EVENT['mask'] & IN_MOVE_SELF)
            {
                // 対象ファイルが切り詰められた？旨のメッセージを設定
                $TARGET_CONF['log_msg'] = "INFO [".$TARGET_CONF['target_service']."] Stop. Target File was rotate? (".$TARGET_CONF['conf_file'].")"."\n";
                // 親プロセスに送信
                ban4ip_sendmsg($TARGET_CONF);
                // ログデータ解析処理を抜ける
                return $TARGET_CONF;
            }
            // ファイルに変更があったのなら
            if (($EVENT['mask'] & IN_MODIFY))
            {
                // 対象ログから読み込み
                $LOGDATA .= fread($TARGET_CONF['target_fp'], 8192);
                
                // 読み込んだログデータを一行ごとのログ配列に格納
                $LOGARRAY = explode("\n", $LOGDATA);
                
                // ログ配列から一行ずつ処理
                foreach($LOGARRAY as $LOGSTR)
                {
                    // データが無いなら
                    if ($LOGSTR == '')
                    {
                        // 飛ばして次の行に行く
                        continue;
                    }
                    // 対象文字列かどうかを検査
                    foreach($TARGET_CONF['target_str'] AS $TARGET_PATTERN)
                    {
                        // 対象文字列があるなら
                        if (preg_match($TARGET_PATTERN, $LOGSTR, $TARGET_MATCH) == 1)
                        {
                            // 対象文字列がキーワード指定なら
                            if (isset($TARGET_CONF['target_type']) && strpos($TARGET_CONF['target_type'], "KEY") !== FALSE)
                            {
                                    // 現在日時を設定
                                    $TARGET_CONF['logtime'] = local_time();
                                    // 対象文字列を対象IPアドレスに設定
                                    $TARGET_CONF['target_keyword'] = $TARGET_MATCH[1];
                                    
                                    // 対象がキーワードなので、IPアドレスがらみの処理とは別に作る
                                    // 文字列でSQLインジェクションの可能性があるので、INSERTとかSELECTするときにフィルターにかける
                                    // あとは…同じかな？
                                    
                                    
                                    // 対象キーワードがホワイトリストの中にあるかどうか確認
                                    if (check_safekeyword($TARGET_CONF) == TRUE)
                                    {
                                        // ホワイトリストである旨のメッセージを設定
                                        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4ip[".getmypid()."]: INFO [".$TARGET_CONF['target_service']."] Safe ".$TARGET_CONF['target_keyword']."\n";
                                        // 親プロセスに送信
                                        ban4ip_sendmsg($TARGET_CONF);
                                        // 次の対象文字列検査へ
                                        continue;
                                    }
                                    
                                    // カウントデータベースから該当サービスの現在時刻 - 対象時間より昔のカウントデータを削除
                                    $TARGET_CONF['count_db']->exec("DELETE FROM count_tbl WHERE service = '".$TARGET_CONF['target_service']."' AND registdate < (".(local_time() - $TARGET_CONF['findtime']).")");
                                    // カウントデータベースにカウント対象キーワードを登録(IPアドレスじゃないのでクエリをエスケープする)
///                                    $TARGET_CONF['count_db']->exec("INSERT INTO count_tbl VALUES ('".sqlite_escape_string($TARGET_CONF['target_keyword'])."','".$TARGET_CONF['target_service']."',".$TARGET_CONF['logtime'].")");
                                    $TARGET_CONF['count_db']->exec("INSERT INTO count_tbl VALUES ('".$TARGET_CONF['target_keyword']."','".$TARGET_CONF['target_service']."',".$TARGET_CONF['logtime'].")");
                                    
                                    // カウントデータベースで対象キーワードが対象時間内に何個存在するか取得
                                    $RESULT = $TARGET_CONF['count_db']->query("SELECT COUNT(address) AS addr_count FROM count_tbl WHERE address = '".$TARGET_CONF['target_keyword']."' AND service = '".$TARGET_CONF['target_service']."' AND registdate > (".($TARGET_CONF['logtime'] - $TARGET_CONF['findtime']).")");
                                    
                                    // 対象キーワードの検出回数を初期化
                                    $RESULT_COUNT = 0;
                                    // 結果が取得できているなら
                                    if ($RESULT)
                                    {
                                        // 結果を取得
                                        $DB_DATA = $RESULT->fetch(PDO::FETCH_ASSOC);
                                        // 対象キーワードの検出回数を取得
                                        $RESULT_COUNT = $DB_DATA['addr_count'];
                                        // 結果を開放
                                        $DB_DATA = $RESULT->closeCursor();
                                    }
                                    // 結果が0なのはおかしい…のでチェックルーチンに飛ぶ
                                    if ($RESULT_COUNT == 0)
                                    {
                                        // 親プロセスにログメッセージを送信
                                        ban4ip_dbcheck($TARGET_CONF);
                                    }
                                    // もし検出回数以上になったら
                                    if ($RESULT_COUNT >= $TARGET_CONF['maxretry'])
                                    {
                                        // BANする
                                        $TARGET_CONF = ban4ip_ban($TARGET_CONF);
                                        // 親プロセスにログメッセージを送信
                                        ban4ip_sendmsg($TARGET_CONF);
                                    }
                                    // 検出回数未満なら
                                    else
                                    {
                                        // 対象キーワードのカウント数のメッセージを設定
                                        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4ip[".getmypid()."]: INFO [".$TARGET_CONF['target_service']."] Found(1) ".$TARGET_CONF['target_keyword']." (".$RESULT_COUNT."/".$TARGET_CONF['maxretry']." counts)"."\n";
                                        // 親プロセスに送信
                                        ban4ip_sendmsg($TARGET_CONF);
                                    }
                            }
                            else
                            {
                                // 対象文字列がIPアドレスなら
                                if (filter_var($TARGET_MATCH[1], FILTER_VALIDATE_IP) !== FALSE)
                                {
                                    // 現在日時を設定
                                    $TARGET_CONF['logtime'] = local_time();
                                    // 対象文字列を対象IPアドレスに設定
                                    $TARGET_CONF['target_address'] = $TARGET_MATCH[1];
                                    // IPアドレスがIPv4inIPv6フォーマットなら
                                    if (preg_match("/^::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/", $TARGET_CONF['target_address']))
                                    {
///                                        print "IPアドレスがIPv4inIPv6フォーマットです\n";
                                        // IPv4アドレスを設定
                                        $TARGET_CONF['target_address'] = preg_replace("/^::ffff:/", '', $TARGET_CONF['target_address']);
                                    }
                                    // ホスト名の逆引きがONになっていたら
                                    if ($TARGET_CONF['hostname_lookup'] == 1)
                                    {
                                        // 対象IPアドレスから対象ホスト名を取得して設定
                                        $TARGET_CONF['target_hostname'] = gethostbyaddr($TARGET_CONF['target_address']);
                                    }
                                    
                                    // 対象IPアドレスがホワイトリストの中にあるかどうか確認
                                    if (check_safeaddr($TARGET_CONF) == TRUE)
                                    {
                                        // ホワイトリストである旨のメッセージを設定
                                        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4ip[".getmypid()."]: INFO [".$TARGET_CONF['target_service']."] Safe ".$TARGET_CONF['target_address']."\n";
                                        // 親プロセスに送信
                                        ban4ip_sendmsg($TARGET_CONF);
                                        // 次の対象文字列検査へ
                                        continue;
                                    }
                                    
                                    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
                                    if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
                                    {
                                        // IPv6マスク値が設定されていて、/128以外(0～127)なら
                                        if (isset($TARGET_CONF['ipv6_netmask']) && ($TARGET_CONF['ipv6_netmask'] >= 0 && $TARGET_CONF['ipv6_netmask'] < 128))
                                        {
                                            // 対象IPアドレスにマスク値を追加したアドレス表記を、対象ネットワークアドレスとする
                                            $TARGET_ADDRESS = get_networkaddr($TARGET_CONF['target_address'], $TARGET_CONF['ipv6_netmask']);
                                            // 対象ネットワークアドレスが正常に取得できたなら
                                            if ($TARGET_ADDRESS != FALSE)
                                            {
                                                // 対象ネットワークアドレスを対象IPアドレスとして設定
                                                $TARGET_CONF['target_address'] = $TARGET_ADDRESS;
                                            }
                                        }
                                    }
                                    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
                                    else if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
                                    {
                                        // IPv4マスク値が設定されていて、/32以外(0～31)なら
                                        if (isset($TARGET_CONF['ipv4_netmask']) && ($TARGET_CONF['ipv4_netmask'] >= 0 && $TARGET_CONF['ipv4_netmask'] < 32))
                                        {
                                            // 対象IPアドレスにマスク値を追加したアドレス表記を、対象ネットワークアドレスとする
                                            $TARGET_ADDRESS = get_networkaddr($TARGET_CONF['target_address'], $TARGET_CONF['ipv4_netmask']);
                                            // 対象ネットワークアドレスが正常に取得できたなら
                                            if ($TARGET_ADDRESS != FALSE)
                                            {
                                                // 対象ネットワークアドレスを対象IPアドレスとして設定
                                                $TARGET_CONF['target_address'] = $TARGET_ADDRESS;
                                            }
                                        }
                                    }
                                    
                                    // カウントデータベースから該当サービスの現在時刻 - 対象時間より昔のカウントデータを削除
                                    $TARGET_CONF['count_db']->exec("DELETE FROM count_tbl WHERE service = '".$TARGET_CONF['target_service']."' AND registdate < (".(local_time() - $TARGET_CONF['findtime']).")");
                                    // カウントデータベースにカウント対象IPアドレスを登録
                                    $TARGET_CONF['count_db']->exec("INSERT INTO count_tbl VALUES ('".$TARGET_CONF['target_address']."','".$TARGET_CONF['target_service']."',".$TARGET_CONF['logtime'].")");
                                    
                                    // カウントデータベースで対象IPアドレスが対象時間内に何個存在するか取得
                                    $RESULT = $TARGET_CONF['count_db']->query("SELECT COUNT(address) AS addr_count FROM count_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND service = '".$TARGET_CONF['target_service']."' AND registdate > (".($TARGET_CONF['logtime'] - $TARGET_CONF['findtime']).")");
                                    
                                    // 対象IPアドレスの検出回数を初期化
                                    $RESULT_COUNT = 0;
                                    // 結果が取得できているなら
                                    if ($RESULT)
                                    {
                                        // 結果を取得
                                        $DB_DATA = $RESULT->fetch(PDO::FETCH_ASSOC);
                                        // 対象IPアドレスの検出回数を取得
                                        $RESULT_COUNT = $DB_DATA['addr_count'];
                                        // 結果を開放
                                        $DB_DATA = $RESULT->closeCursor();
                                    }
                                    // 結果が0なのはおかしい…のでチェックルーチンに飛ぶ
                                    if ($RESULT_COUNT == 0)
                                    {
                                        // 親プロセスにログメッセージを送信
                                        ban4ip_dbcheck($TARGET_CONF);
                                    }
                                    // もし検出回数以上になったら
                                    if ($RESULT_COUNT >= $TARGET_CONF['maxretry'])
                                    {
                                        // BANする
                                        $TARGET_CONF = ban4ip_ban($TARGET_CONF);
                                        // 親プロセスにログメッセージを送信
                                        ban4ip_sendmsg($TARGET_CONF);
                                    }
                                    // 検出回数未満なら
                                    else
                                    {
                                        // 対象IPアドレスのカウント数のメッセージを設定
                                        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4ip[".getmypid()."]: INFO [".$TARGET_CONF['target_service']."] Found(3) ".$TARGET_CONF['target_address']." (".$RESULT_COUNT."/".$TARGET_CONF['maxretry']." counts)"."\n";
                                        // 親プロセスに送信
                                        ban4ip_sendmsg($TARGET_CONF);
                                    }
                                }
                            }
                        }
                    }
                }
                // 行の途中かもしれないのでログデータに戻す
                $LOGDATA = $LOGSTR;
            }
        }
    }
    // パラメータを戻す
    return $TARGET_CONF;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_init($TARGET_CONF)
{
    // ログメッセージを初期化
    $TARGET_CONF['log_msg'] = '';
    
    // BAN時間[s](--bantime)が設定されていないなら
    if (!isset($TARGET_CONF['bantime']))
    {
        // エラーメッセージに、BAN時間[s]の設定がない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] bantime is not set!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    // BAN時間[s]が数字ではないなら(もっと厳密にチェックする？)
    else if (!is_numeric($TARGET_CONF['bantime']))
    {
        // エラーメッセージに、BAN時間[s]の設定がない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] bantime is not integer!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    
    
    // 対象プロトコル(--protcol)が設定されているなら
    if (isset($TARGET_CONF['target_protcol']))
    {
        // 対象プロトコルが文字列指定でないか、tcpでもudpでもallでもないなら
        if (!is_string($TARGET_CONF['target_protcol']) || ($TARGET_CONF['target_protcol'] != 'tcp' && $TARGET_CONF['target_protcol'] != 'udp' && $TARGET_CONF['target_protcol'] != 'all'))
        {
            // エラーメッセージに、BAN時間[s]の設定がない旨を設定
            $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] ".$TARGET_CONF['target_protcol']." is not support protcol!? (".$TARGET_CONF['conf_file'].")"."\n";
            // パラメータを戻す
            return $TARGET_CONF;
        }
    }
    //対象ポートが設定されていないなら
    else
    {
        // 全ポート(-1)をBAN対象として設定
        $TARGET_CONF['target_protcol'] = 'all';
    }
    
    
    // 対象ポート(--port)が設定されているなら
    if (isset($TARGET_CONF['target_port']))
    {
        // 対象ポートが数字ではなく(＝文字列指定の)、ポート番号が引けないか、'all'でないなら
        if (!is_numeric($TARGET_CONF['target_port']) && (getservbyname($TARGET_CONF['target_port'],'tcp') == FALSE && $TARGET_CONF['target_port'] != 'all'))
        {
            // エラーメッセージに、BAN時間[s]の設定がない旨を設定
            $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] ".$TARGET_CONF['target_protcol']." is not support port!? (".$TARGET_CONF['conf_file'].")"."\n";
             // パラメータを戻す
            return $TARGET_CONF;
       }
    }
    //対象ポートが設定されていないなら
    else
    {
        // 全ポート(-1)をBAN対象として設定
        $TARGET_CONF['target_port'] = 'all';
    }
    
    
    // 必須パラメータ
    // 対象ルール(--rule)が設定されていないなら
    if (!isset($TARGET_CONF['target_rule']))
    {
        // エラーメッセージに、BAN時間[s]の設定がない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Rule is not set!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    // 対象ルールが文字列指定だった場合、DROPでもREJECTでもLOGでもないなら
    else if (!is_string($TARGET_CONF['target_rule']) || ($TARGET_CONF['target_rule'] != 'DROP' && $TARGET_CONF['target_rule'] != 'REJECT' && $TARGET_CONF['target_rule'] != 'LOG'))
    {
        // エラーメッセージに、BAN時間[s]の設定がない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Rule is not support rule!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    
    
    // デーモンでは必須パラメータ
    // 対象サービス(--service)が設定されていないなら
    if (!isset($TARGET_CONF['target_service']))
    {
        // エラーメッセージに、BAN時間[s]の設定がない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] target_service is not set!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    
    // 対象プロトコルと対象ポートが片方だけallなら
    if (
        ($TARGET_CONF['target_protcol'] != 'all' && $TARGET_CONF['target_port'] == 'all') ||
        ($TARGET_CONF['target_protcol'] == 'all' && $TARGET_CONF['target_port'] != 'all')
        )
    {
        // エラーメッセージに、BAN時間[s]の設定がない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] protcol(".$TARGET_CONF['target_protcol'].") and port(".$TARGET_CONF['target_port'].") mismatch!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    
    // --------------------------------
    
    // UNIXソケットを開く
    $TARGET_CONF['socket'] = socket_create(AF_UNIX, SOCK_DGRAM, 0);
    // UNIXソケットが開けなかったら
    if ($TARGET_CONF['socket'] == FALSE )
    {
        // エラーメッセージに、UNIXソケットを開けない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Cannot create socket!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    // UNIXソケットをブロックモードに変更できなかったら
    if (socket_set_block($TARGET_CONF['socket']) == FALSE)
    {
        // エラーメッセージに、UNIXソケットをブロックモードモードに変更できない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Cannot set block socket!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    // UNIXソケットの接続を確立できるまで無限ループ(@をつけてエラー出力を抑制)
    while(@socket_connect($TARGET_CONF['socket'], $TARGET_CONF['socket_file']) == FALSE)
    {
        // 100msくらいのウェイトを置く
        usleep(100000);
    }
    
    // --------------------------------
    
    // 対象ログがないなら
    if (!is_file($TARGET_CONF['target_log']))
    {
        // エラーメッセージに、対象ログが開けない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Cannot find target_log!? (".$TARGET_CONF['conf_file'].")"."\n";
        // 100msくらいのウェイトを置く
        usleep(100000);
        // パラメータを戻す
        return $TARGET_CONF;
    }
    // 対象ログが読めない状態なら(ログローテートした可能性あり)
    if (!is_readable($TARGET_CONF['target_log']))
    {
        // エラーメッセージに、対象ログが読めない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Cannot read target_log!? (".$TARGET_CONF['conf_file'].")"."\n";
        // 100msくらいのウェイトを置く
        usleep(100000);
        // パラメータを戻す
        return $TARGET_CONF;
    }
    // 対象ログを開く
    $TARGET_CONF['target_fp'] = fopen($TARGET_CONF['target_log'], "r");
    // 対象ログが開けなかったら
    if ($TARGET_CONF['target_fp'] == FALSE)
    {
        // エラーメッセージに、対象ログが開けない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Cannot open target_log!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    
    // 対象ログの最後にシーク
    $RESULT = fseek($TARGET_CONF['target_fp'], 0, SEEK_END);
    // 対象ログの最後にシークできなかったら
    if ($RESULT == -1)
    {
        // エラーメッセージに、対象ログの最後にシークできない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Cannot seek target_log!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    
    // inotifyモジュール初期化
    $TARGET_CONF['target_inotify'] = inotify_init();
    // 失敗したなら
    if ($TARGET_CONF['target_inotify'] === false)
    {
        // エラーメッセージに、対象ログの最後にシークできない旨を設定
        $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Failed to obtain an inotify instance!? (".$TARGET_CONF['conf_file'].")"."\n";
        // パラメータを戻す
        return $TARGET_CONF;
    }
    else
    {
        // 指定ファイルに変化があったらイベントを起こすように設定(IN_MODIFYは追記があったとき、IN_MOVE_SELFはlogrotateで切り詰めがあったとき)
        $TARGET_CONF['target_watch'] = inotify_add_watch($TARGET_CONF['target_inotify'], $TARGET_CONF['target_log'], IN_MODIFY | IN_MOVE_SELF);
        
        // 設定が失敗したら
        if ($TARGET_CONF['target_watch'] === false)
        {
            // エラーメッセージに、イベントを起こすように設定できない旨を設定
            $TARGET_CONF['log_msg'] .= "ERROR [".$TARGET_CONF['target_service']."] Cannot watch target_log!? (".$TARGET_CONF['conf_file'].")"."\n";
            // パラメータを戻す
            return $TARGET_CONF;
        }
    }
    // パラメータを戻す
    return $TARGET_CONF;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_start($TARGET_CONF)
{
    do // loop_mode=1なら、ログ切りつめでも動作し続ける
    {
        // 対象ログの監視＆BAN処理の初期化
        $TARGET_CONF = ban4ip_init($TARGET_CONF);
        // 初期化に失敗したら
        if (strlen($TARGET_CONF['log_msg']))
        {
            // 設定されている宛先にメール送信
            foreach($TARGET_CONF['mail_to'] as $MAIL_TO)
            {
///                $RESULT = mb_send_mail(
                $RESULT = ban4ip_mail_send(
                $TARGET_CONF,
                $MAIL_TO,
                $TARGET_CONF['mail_title']." ".$TARGET_CONF['log_msg'],
                date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ".$TARGET_CONF['log_msg'],
                'From: '.$TARGET_CONF['mail_from']."\n".
                $TARGET_CONF['mail_priority']."\n");
            }
            // メッセージを表示
            print date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ".$TARGET_CONF['log_msg'];
            // 親プロセスに送信
            ban4ip_sendmsg($TARGET_CONF);
            // loop_mode!=1なら、ログがない場合にはここで終わり
            if ($TARGET_CONF['loop_mode'] != 1)
            {
                // 終わり
                exit;
            }
        }
        // 成功したら
        else
        {
            // 子プロセスがスタートした旨を表示
            $TARGET_CONF['log_msg'] = "INFO [".$TARGET_CONF['target_service']."] Co-Process Start. (".$TARGET_CONF['conf_file'].")"."\n";
            // 親プロセスに送信
            ban4ip_sendmsg($TARGET_CONF);
            
            // 対象ログの監視＆BAN処理開始
            $TARGET_CONF = ban4ip_loop($TARGET_CONF);
        }
        // 対象ログの監視＆BAN処理の終了処理
        $TARGET_CONF = ban4ip_close($TARGET_CONF);
    }
    while ($TARGET_CONF['loop_mode'] == 1);
}
?>
